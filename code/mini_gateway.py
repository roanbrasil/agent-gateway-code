"""A toy agent gateway in ~120 lines: registry (control plane) + proxy (data plane).

It is NOT a production gateway. It exists to make five ideas concrete:
  1. bundles + filters decide what an agent SEES (tools/list)
  2. policy is re-checked when the agent ACTS (tools/call)
  3. the credential is injected by the gateway and never reaches the agent
  4. a missing per-user grant is a recoverable state (input_required), not a failed turn
  5. every call leaves one structured audit event
"""
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field

SECRET = b"rotate-me"  # signs requestState; in real life this lives in a KMS


@dataclass
class Server:                      # a downstream MCP server, as the registry sees it
    name: str
    tools: dict                    # tool name -> {"description", "inputSchema", "readOnly"}
    auth_mode: str                 # "gateway_token" | "per_user_oauth"
    owner: str
    handler: callable              # (tool, args, credential) -> result


@dataclass
class Caller:
    agent: str
    user: str
    can_write: bool = False


@dataclass
class Registry:                    # control plane: source of truth, edited by tool owners
    servers: dict = field(default_factory=dict)
    bundles: dict = field(default_factory=dict)       # bundle -> {server: [approved tool names]}
    vault: dict = field(default_factory=dict)         # server -> gateway-held token
    grants: dict = field(default_factory=dict)        # (user, server) -> per-user OAuth token
    rate_limit: int = 3                               # calls per caller per window


class Gateway:                     # data plane: enforces what the registry says
    def __init__(self, registry: Registry):
        self.reg, self.audit, self.calls = registry, [], {}

    # ---- discovery -------------------------------------------------------
    def list_tools(self, caller: Caller, bundle: str) -> dict:
        tools = []
        for server_name, approved in self.reg.bundles[bundle].items():   # fan-out
            server = self.reg.servers[server_name]
            for tool_name in approved:
                spec = server.tools[tool_name]
                if not spec["readOnly"] and not caller.can_write:        # filter
                    continue
                tools.append({"name": f"{server_name}__{tool_name}",     # namespace
                              "description": spec["description"],
                              "inputSchema": spec["inputSchema"]})
        tools.sort(key=lambda t: t["name"])           # deterministic order helps prompt caching
        # the catalog depends on WHO is asking, so shared caches must not reuse it
        return {"tools": tools, "ttlMs": 60_000, "cacheScope": "private"}

    # ---- invocation ------------------------------------------------------
    def call_tool(self, caller: Caller, bundle: str, name: str, args: dict,
                  request_state: str | None = None) -> dict:
        server_name, _, tool_name = name.partition("__")
        event = {"ts": time.time(), "agent": caller.agent, "user": caller.user,
                 "bundle": bundle, "server": server_name, "tool": tool_name}

        def finish(decision: str, result: dict) -> dict:
            server = self.reg.servers.get(server_name)
            self.audit.append({**event, "decision": decision,
                               "owner": server.owner if server else None})
            return result

        # 1. authorize again: showing up in a catalog is not permission to execute
        if tool_name not in self.reg.bundles[bundle].get(server_name, []):
            return finish("deny:not_in_bundle", {"isError": True, "error": "tool not available"})
        server = self.reg.servers[server_name]
        if not server.tools[tool_name]["readOnly"] and not caller.can_write:
            return finish("deny:write_not_allowed", {"isError": True, "error": "write not allowed"})

        # 2. rate limit per caller
        key = (caller.agent, caller.user)
        self.calls[key] = self.calls.get(key, 0) + 1
        if self.calls[key] > self.reg.rate_limit:
            return finish("deny:rate_limited", {"isError": True, "error": "rate limited"})

        # 3. pick the credential; the agent never sees it
        if server.auth_mode == "gateway_token":
            credential = self.reg.vault[server_name]
        else:  # per_user_oauth
            credential = self.reg.grants.get((caller.user, server_name))
            if credential is None:
                state = _sign({"user": caller.user, "tool": name, "exp": time.time() + 300})
                return finish("input_required", {
                    "resultType": "input_required",
                    "inputRequests": {"connect": {"method": "elicitation/create", "params": {
                        "mode": "url", "message": f"Connect your {server_name} account",
                        "url": f"https://gateway.example/connect/{server_name}"}}},
                    "requestState": state})
            if request_state is not None and not _verify(request_state, caller.user, name):
                return finish("deny:bad_request_state", {"isError": True, "error": "invalid state"})

        # 4. forward
        result = server.handler(tool_name, args, credential)
        return finish("allow", {"resultType": "complete", "content": result})


def _sign(payload: dict) -> str:
    body = json.dumps(payload, sort_keys=True)
    mac = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    return f"{body}|{mac}"


def _verify(state: str, user: str, tool: str) -> bool:
    body, _, mac = state.rpartition("|")
    expected = hmac.new(SECRET, body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, expected):
        return False                                   # tampered
    payload = json.loads(body)
    return payload["user"] == user and payload["tool"] == tool and payload["exp"] > time.time()
