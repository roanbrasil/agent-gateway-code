# Mini agent gateway + tool-catalog token counter

    git clone --depth 1 https://github.com/github/github-mcp-server.git
    SNAPS=github-mcp-server/pkg/github/__toolsnaps__

    # 1. token cost of the catalog (needs Node; tokenizer: o200k_base)
    npm i gpt-tokenizer
    node count_tool_tokens.js $SNAPS

    # 2. toy gateway checks (Python 3.10+, no dependencies)
    python test_gateway.py $SNAPS

Numbers in the article were measured at commit f10e4e1 (2026-10-02): 131 tools, 29,454 tokens.
`github_tool_tokens.json` holds the per-tool counts from that run.
