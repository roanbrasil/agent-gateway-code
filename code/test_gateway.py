"""Runs the toy gateway against the REAL tool schemas of github/github-mcp-server.

Usage:  python test_gateway.py /path/to/github-mcp-server/pkg/github/__toolsnaps__
"""
import glob
import json
import os
import sys

from mini_gateway import Caller, Gateway, Registry, Server

snap_dir = sys.argv[1]
github_tools = {}
for path in glob.glob(os.path.join(snap_dir, "*.snap")):
    d = json.load(open(path))
    github_tools[d["name"]] = {"description": d["description"], "inputSchema": d["inputSchema"],
                               "readOnly": bool(d.get("annotations", {}).get("readOnlyHint"))}

seen = []                                             # what each downstream actually received


def downstream(server):
    def handler(tool, args, credential):
        seen.append((server, tool, credential))
        return [{"type": "text", "text": f"{server}.{tool} ok"}]
    return handler


tracker_tools = {
    "get_ticket": {"description": "Read one ticket.", "readOnly": True,
                   "inputSchema": {"type": "object", "properties": {"id": {"type": "string"}}}},
    "delete_project": {"description": "Delete a whole project.", "readOnly": False,
                       "inputSchema": {"type": "object", "properties": {"key": {"type": "string"}}}},
}

reg = Registry()
reg.servers["github"] = Server("github", github_tools, "gateway_token", "dev-platform", downstream("github"))
reg.servers["tracker"] = Server("tracker", tracker_tools, "per_user_oauth", "eng-productivity", downstream("tracker"))
reg.vault["github"] = "ghs_SECRET_GATEWAY_TOKEN"
reg.bundles["developer-tools"] = {
    "github": ["create_pull_request", "get_file_contents", "issue_read",
               "list_issues", "pull_request_read", "search_code"],
    "tracker": ["get_ticket"],
}
gw = Gateway(reg)
writer = Caller(agent="coding-agent", user="ana", can_write=True)
reader = Caller(agent="triage-bot", user="ana", can_write=False)

# 1. discovery: the agent sees 7 tools out of 133, namespaced
cat = gw.list_tools(writer, "developer-tools")
names = [t["name"] for t in cat["tools"]]
assert len(names) == 7 and "github__create_pull_request" in names
assert "github__delete_repository" not in names and cat["cacheScope"] == "private"
print(f"1. catalog for writer: {len(names)} of {len(github_tools) + len(tracker_tools)} tools")

# 2. filter by caller: the read-only agent does not even see the write tool
names_ro = [t["name"] for t in gw.list_tools(reader, "developer-tools")["tools"]]
assert "github__create_pull_request" not in names_ro and len(names_ro) == 6
print(f"2. catalog for reader: {len(names_ro)} tools (write tool hidden)")

# 3. hidden is not enough: guessing a tool name is denied at call time
r = gw.call_tool(writer, "developer-tools", "github__delete_repository", {"owner": "x", "repo": "y"})
assert r["isError"] and gw.audit[-1]["decision"] == "deny:not_in_bundle"
r = gw.call_tool(reader, "developer-tools", "github__create_pull_request", {})
assert r["isError"] and gw.audit[-1]["decision"] == "deny:write_not_allowed"
assert seen == []                                      # nothing reached a downstream
print("3. guessed/forbidden tool names denied at tools/call; downstream never contacted")

# 4. credential injection: downstream gets the token, the agent and the audit log do not
r = gw.call_tool(writer, "developer-tools", "github__search_code", {"query": "TODO"})
assert r["resultType"] == "complete" and seen[-1][2] == "ghs_SECRET_GATEWAY_TOKEN"
assert "ghs_" not in json.dumps(r) and "ghs_" not in json.dumps(gw.audit)
print("4. token reached downstream; absent from the result and from the audit log")

# 5. missing per-user grant is recoverable: input_required -> user connects -> retry succeeds
r1 = gw.call_tool(writer, "developer-tools", "tracker__get_ticket", {"id": "ENG-1"})
assert r1["resultType"] == "input_required" and r1["inputRequests"]["connect"]["params"]["mode"] == "url"
reg.grants[("ana", "tracker")] = "user-oauth-token-ana"          # user finished the browser flow
forged = r1["requestState"].replace('"user": "ana"', '"user": "bob"')
bad = gw.call_tool(writer, "developer-tools", "tracker__get_ticket", {"id": "ENG-1"}, forged)
assert bad["isError"] and gw.audit[-1]["decision"] == "deny:bad_request_state"
reg.rate_limit = 10                                               # keep step 6 independent
r2 = gw.call_tool(writer, "developer-tools", "tracker__get_ticket", {"id": "ENG-1"}, r1["requestState"])
assert r2["resultType"] == "complete" and seen[-1] == ("tracker", "get_ticket", "user-oauth-token-ana")
print("5. input_required -> connect -> retry ok; tampered requestState rejected")

# 6. rate limit
reg.rate_limit, gw.calls = 2, {}
decisions = [gw.call_tool(reader, "developer-tools", "github__issue_read", {}) and gw.audit[-1]["decision"]
             for _ in range(3)]
assert decisions == ["allow", "allow", "deny:rate_limited"]
print(f"6. rate limit: {decisions}")

# 7. every call left exactly one event with an owner to page
assert all(e["owner"] for e in gw.audit) and len(gw.audit) == 9
print(f"7. audit events: {len(gw.audit)}, e.g. {json.dumps({k: gw.audit[0][k] for k in ('agent', 'user', 'server', 'tool', 'decision', 'owner')})}")
print("ALL CHECKS PASSED")
