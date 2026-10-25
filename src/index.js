// archiehq-mcp: a remote MCP server with memo, upload and transcribe tools, and its own OAuth sign-in.

import { json, html, esc } from "./util.js";
import { handleMcp, MODERN, LEGACY } from "./mcp.js";
import { TOOLS } from "./tools.js";
import { protectedResourceMetadata, authorizationServerMetadata, register, authorizeGet, authorizePost, token, revoke, page } from "./oauth.js";

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET, POST, OPTIONS",
  "access-control-allow-headers": "authorization, content-type, accept, mcp-protocol-version, mcp-method, mcp-name, mcp-session-id, last-event-id",
  "access-control-expose-headers": "www-authenticate, mcp-protocol-version",
  "access-control-max-age": "86400",
};

function withCors(res) {
  const r = new Response(res.body, res);
  for (const [k, v] of Object.entries(CORS)) r.headers.set(k, v);
  return r;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const corsPaths = path === "/mcp" || path === "/token" || path === "/register" || path === "/revoke" || path.startsWith("/.well-known/") || path.startsWith("/f/");
    if (request.method === "OPTIONS" && corsPaths) return new Response(null, { status: 204, headers: CORS });
    let res;
    try {
      res = await route(request, env, url, path);
    } catch (e) {
      console.error("unhandled", e?.stack || e);
      res = json({ error: "server_error", error_description: "internal error" }, 500);
    }
    return corsPaths ? withCors(res) : res;
  },
};

async function route(request, env, url, path) {
  const m = request.method;
  if (path === "/mcp") return handleMcp(request, env);

  if (path === "/.well-known/oauth-protected-resource" || path === "/.well-known/oauth-protected-resource/mcp")
    return json(protectedResourceMetadata(env), 200, { "cache-control": "public, max-age=300" });
  if (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration")
    return json(authorizationServerMetadata(env), 200, { "cache-control": "public, max-age=300" });

  if (path === "/register" && m === "POST") return register(request, env);
  if (path === "/authorize" && m === "GET") return authorizeGet(request, env);
  if (path === "/authorize" && m === "POST") return authorizePost(request, env);
  if (path === "/token" && m === "POST") return token(request, env);
  if (path === "/revoke" && m === "POST") return revoke(request, env);

  if (path.startsWith("/f/") && (m === "GET" || m === "HEAD")) return serveFile(request, env, path);
  if (path === "/plan" && m === "GET") return html(planPage(env), 200, { "cache-control": "public, max-age=300" });
  if (path === "/" && m === "GET") return Response.redirect(`${env.ORIGIN}/plan`, 302);
  if (path === "/favicon.ico") return new Response(null, { status: 204 });
  return json({ error: "not_found" }, 404);
}

async function serveFile(request, env, path) {
  const id = path.split("/")[2] || "";
  if (!/^f_[A-Za-z0-9_-]+$/.test(id)) return json({ error: "not_found" }, 404);
  const range = request.headers.get("range");
  let r2range;
  const rm = range && range.match(/^bytes=(\d*)-(\d*)$/);
  if (rm && (rm[1] || rm[2])) r2range = rm[1] ? { offset: Number(rm[1]), ...(rm[2] ? { length: Number(rm[2]) - Number(rm[1]) + 1 } : {}) } : { suffix: Number(rm[2]) };
  const obj = request.method === "HEAD" ? await env.FILES.head(id) : await env.FILES.get(id, r2range ? { range: r2range } : {});
  if (!obj) return json({ error: "not_found" }, 404);
  const headers = new Headers();
  headers.set("content-type", obj.httpMetadata?.contentType || "application/octet-stream");
  headers.set("content-disposition", `inline; filename="${(obj.customMetadata?.filename || id).split("/").pop().replace(/"/g, "")}"`);
  headers.set("x-content-type-options", "nosniff");
  headers.set("content-security-policy", "sandbox; default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'");
  headers.set("cache-control", "public, max-age=3600");
  headers.set("accept-ranges", "bytes");
  headers.set("etag", obj.httpEtag);
  if (request.method === "HEAD") {
    headers.set("content-length", String(obj.size));
    return new Response(null, { status: 200, headers });
  }
  if (r2range && obj.range) {
    const off = obj.range.offset ?? obj.size - obj.range.length;
    const len = obj.range.length ?? obj.size - off;
    headers.set("content-range", `bytes ${off}-${off + len - 1}/${obj.size}`);
    headers.set("content-length", String(len));
    return new Response(obj.body, { status: 206, headers });
  }
  headers.set("content-length", String(obj.size));
  return new Response(obj.body, { status: 200, headers });
}

function planPage(env) {
  const o = env.ORIGIN;
  const rows = TOOLS.map(
    (t) =>
      `<tr><td><code>${esc(t.name)}</code></td><td>${esc(t.description)}<br><span class="muted">Input: ${esc(
        Object.keys(t.inputSchema.properties).map((k) => (t.inputSchema.required.includes(k) ? k : k + "?")).join(", "),
      )} · Result: ${esc(Object.keys(t.outputSchema.properties).join(", "))}</span></td></tr>`,
  ).join("");
  return page(
    "Archie's MCP server — plan",
    `<h1>Archie's MCP server</h1>
<p>A remote <a href="https://modelcontextprotocol.io/specification" style="color:var(--accent)">Model Context Protocol</a> server that gives Archie's tools one home that does not sleep. Owner: Archie (archie.hqr@gmail.com), for the MEGA.dev course.</p>
<div class="card">
<p style="margin:0"><strong>MCP endpoint:</strong> <code>${esc(o)}/mcp</code> (Streamable HTTP, POST only)</p>
<p style="margin:6px 0 0"><strong>Protocol:</strong> ${esc(MODERN.join(", "))} (stateless, per-request <code>_meta</code>, <code>server/discover</code>); older clients: ${esc(LEGACY.join(", "))} with <code>initialize</code>.</p>
</div>

<h2>What the tools do</h2>
<table>${rows}</table>
<p class="muted">Every successful tool result carries <code>structuredContent</code> that matches the tool's <code>outputSchema</code>, plus the same JSON as text. Errors come back with <code>isError: true</code> and a message that says what to fix. Limit: 60 tool calls per minute per app.</p>

<h2>How sign-in works</h2>
<ol>
<li>Calls to <code>/mcp</code> without a valid token get <code>401</code> with <code>WWW-Authenticate: Bearer resource_metadata="${esc(o)}/.well-known/oauth-protected-resource"</code>.</li>
<li>That protected resource metadata names this host as the authorization server: <code>${esc(o)}/.well-known/oauth-authorization-server</code>.</li>
<li>Apps identify themselves with a Client ID Metadata Document (an https <code>client_id</code> URL) or register with Dynamic Client Registration at <code>/register</code>.</li>
<li>OAuth 2.1 authorization code flow with PKCE (<code>S256</code> only). The <code>resource</code> parameter must be <code>${esc(o)}/mcp</code>; tokens only work here. Responses carry <code>iss</code> (RFC 9207).</li>
<li>The consent page shows the app and where it sends you back. <strong>Only the owner can let an app in</strong>: approving needs the owner passphrase.</li>
<li>Access tokens last 1 hour. Refresh tokens last 30 days and rotate on every use. Tokens are random strings; the server stores only their SHA-256 hash.</li>
</ol>

<h2>What data it keeps</h2>
<table>
<tr><th>Data</th><th>Where</th><th>How long</th></tr>
<tr><td>Notes from <code>memo_write</code>: text, time, and the name and id of the app that saved them</td><td>Cloudflare D1</td><td>Until the owner deletes them</td></tr>
<tr><td>Files from <code>upload</code>: content, name, type, size, time, app id. <strong>Anyone with the link can open a file.</strong></td><td>Cloudflare R2</td><td>Until the owner deletes them</td></tr>
<tr><td>Audio for <code>transcribe</code>: downloaded, sent to Whisper on Cloudflare Workers AI, not stored. The transcript is returned, not saved.</td><td>Memory only</td><td>The length of the call</td></tr>
<tr><td>OAuth: registered apps; hashes of codes and tokens</td><td>Cloudflare KV</td><td>Codes 5 min, access 1 h, refresh 30 days; apps until deleted</td></tr>
<tr><td>Request logs (path, status, errors; no tokens, no note text)</td><td>Cloudflare Workers logs</td><td>Cloudflare's log retention</td></tr>
</table>
<p class="muted">Notes are shared by every app the owner lets in. Do not save secrets in them. Nothing is sold or shared with third parties. Source: <a href="https://github.com/ArchieHQR/archiehq-mcp" style="color:var(--accent)">github.com/ArchieHQR/archiehq-mcp</a>.</p>`,
  );
}
