# archiehq-mcp

Archie's remote MCP server: one home for the tools, reachable over HTTPS at
**https://mcp.archiehq.pl/mcp**. Plan page (tools, sign-in, data kept): https://mcp.archiehq.pl/plan

- Cloudflare Worker, no framework. MCP revision **2026-07-28** (stateless, per-request `_meta`,
  `server/discover`, `Mcp-Method`/`Mcp-Name` header checks), plus legacy `initialize` for
  2025-11-25 / 2025-06-18 / 2025-03-26 clients.
- Own OAuth 2.1 authorization server on the same host: protected resource metadata (RFC 9728),
  AS metadata (RFC 8414), Client ID Metadata Documents + Dynamic Client Registration, PKCE S256,
  resource indicators (RFC 8707), `iss` in responses (RFC 9207), rotating refresh tokens.
  The owner lets a client in with the owner passphrase on the consent page.
- Tools (each with `inputSchema` + `outputSchema`, results as `structuredContent`):

| tool | input | result |
|---|---|---|
| `memo_write` | `{ text }` | `{ id, created_at }` |
| `memo_search` | `{ query, limit? }` | `{ notes: [{ id, text, created_at, author }] }` |
| `upload` | `{ content, filename?, encoding?, content_type? }` | `{ url, id, filename, content_type, size }` |
| `transcribe` | `{ url, language? }` | `{ segments: [{ start, end, text }], language, duration }` |

Storage: D1 (notes), R2 (files, public links at `/f/<id>/<name>`), KV (OAuth, hashed tokens),
Workers AI `@cf/openai/whisper-large-v3-turbo` (transcribe).

## Deploy

```bash
npx wrangler d1 execute archiehq-mcp --remote --file schema.sql
npx wrangler secret put OWNER_PASSPHRASE
npx wrangler deploy
```

## Test

```bash
# local: .dev.vars with OWNER_PASSPHRASE=<test value> and ORIGIN=http://localhost:8787
npx wrangler dev
BASE=http://localhost:8787 PASSPHRASE=<test value> AUDIO=clip.mp3 node test/flow.mjs
```
