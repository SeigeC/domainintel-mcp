# DomainIntel MCP

AI agent-callable domain intelligence. Two tools: `domain_whois` (RDAP/WHOIS) and `domain_dns` (DNS-over-HTTPS). Built in Go, runs locally over stdio.

## Tools

| Tool | Purpose | Parameters |
|---|---|---|
| `domain_whois` | RDAP/WHOIS lookup: registrar, registration/expiration dates, nameservers, domain status | `domain` (string, required) — e.g. `example.com` |
| `domain_dns` | DNS record query (A, NS, CNAME, MX, TXT, AAAA, CAA, SOA) | `domain` (string, required); `type` (enum, default `"A"`) |

## Install

```bash
git clone https://github.com/SeigeC/domainintel-mcp
cd domainintel-mcp
go build -o domainintel-mcp .
```

No API keys required. WHOIS uses the public rdap.org service; DNS uses dns.google.

## Claude Desktop config

```json
{
  "mcpServers": {
    "domainintel": {
      "command": "/path/to/domainintel-mcp",
      "args": []
    }
  }
}
```

Restart Claude Desktop after adding the config. Tools appear automatically when a conversation needs domain intelligence.

## Cursor / VS Code

```json
{
  "mcpServers": {
    "domainintel": {
      "command": "/path/to/domainintel-mcp",
      "args": []
    }
  }
}
```

Place in `.cursor/mcp.json` (Cursor) or `.vscode/mcp.json` (VS Code).

## License

MIT — see [LICENSE](LICENSE).
