#!/usr/bin/env node
// Command-line MCP client for this server, for files too big to pass through a model's context.
// It signs in through the server's own OAuth (owner approves once), then calls tools directly.
//
//   node cli/archiehq-mcp.mjs login
//   node cli/archiehq-mcp.mjs upload <path> [--name logs/day.log] [--type text/plain]
//   node cli/archiehq-mcp.mjs call <tool> '<json arguments>'
//
// Env: MCP_BASE (default https://mcp.archiehq.pl), MCP_CLI_STATE (default ./.archiehq-mcp-cli.json; keep it private).

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";

const BASE = (process.env.MCP_BASE || "https://mcp.archiehq.pl").replace(/\/+$/, "");
const STATE = process.env.MCP_CLI_STATE || ".archiehq-mcp-cli.json";
const VERSION = "2026-07-28";
const b64url = (b) => Buffer.from(b).toString("base64url");

const load = () => (existsSync(STATE) ? JSON.parse(readFileSync(STATE, "utf8")) : {});
const save = (s) => writeFileSync(STATE, JSON.stringify(s, null, 2), { mode: 0o600 });

async function discover() {
  const r = await fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
  const prmUrl = (r.headers.get("www-authenticate") || "").match(/resource_metadata="([^"]+)"/)?.[1] || `${BASE}/.well-known/oauth-protected-resource`;
  const prm = await (await fetch(prmUrl)).json();
  const as = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
  return { prm, as };
}

function openBrowser(url) {
  const cmd = process.platform === "win32" ? ["rundll32", ["url.dll,FileProtocolHandler", url]] : process.platform === "darwin" ? ["open", [url]] : ["xdg-open", [url]];
  try {
    spawn(cmd[0], cmd[1], { detached: true, stdio: "ignore" }).unref();
  } catch {}
}

async function login() {
  const { prm, as } = await discover();
  const server = createServer();
  await new Promise((res) => server.listen(0, "127.0.0.1", res));
  const redirect = `http://127.0.0.1:${server.address().port}/callback`;
  const reg = await fetch(as.registration_endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ client_name: "archiehq-mcp CLI", redirect_uris: [redirect], token_endpoint_auth_method: "none", application_type: "native", grant_types: ["authorization_code", "refresh_token"] }),
  });
  if (reg.status !== 201) throw new Error(`registration failed: HTTP ${reg.status} ${await reg.text()}`);
  const client = await reg.json();
  const verifier = b64url(randomBytes(32));
  const state = b64url(randomBytes(16));
  const u = new URL(as.authorization_endpoint);
  const q = { response_type: "code", client_id: client.client_id, redirect_uri: redirect, code_challenge: b64url(createHash("sha256").update(verifier).digest()), code_challenge_method: "S256", state, scope: prm.scopes_supported?.join(" ") || "", resource: prm.resource };
  for (const [k, v] of Object.entries(q)) u.searchParams.set(k, v);
  console.log(`Open this page and approve (it should open by itself):\n${u}\n`);
  openBrowser(u.toString());
  const params = await new Promise((resolve) => {
    server.on("request", (req, res) => {
      const p = new URL(req.url, redirect).searchParams;
      if (!new URL(req.url, redirect).pathname.endsWith("/callback")) return res.writeHead(404).end();
      res.writeHead(200, { "content-type": "text/plain" }).end(p.get("error") ? `Sign-in failed: ${p.get("error")}. You can close this tab.` : "Signed in. You can close this tab.");
      resolve(p);
    });
  });
  server.close();
  if (params.get("state") !== state) throw new Error("state mismatch");
  if (params.get("iss") && params.get("iss") !== as.issuer) throw new Error("iss mismatch");
  if (params.get("error")) throw new Error(`sign-in refused: ${params.get("error")} ${params.get("error_description") || ""}`);
  const tok = await tokenRequest(as, { grant_type: "authorization_code", code: params.get("code"), redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier, resource: prm.resource });
  save({ base: BASE, token_endpoint: as.token_endpoint, resource: prm.resource, client_id: client.client_id, ...tok });
  console.log(`Signed in. Credentials saved to ${STATE}.`);
}

async function tokenRequest(as, body) {
  const r = await fetch(as.token_endpoint, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(body) });
  const j = await r.json();
  if (!r.ok) throw new Error(`token request failed: ${j.error} ${j.error_description || ""}`);
  return { access_token: j.access_token, refresh_token: j.refresh_token, expires_at: Date.now() + (j.expires_in - 60) * 1000 };
}

async function accessToken() {
  const s = load();
  if (!s.refresh_token) throw new Error("not signed in: run `login` first");
  if (s.access_token && s.expires_at > Date.now()) return s.access_token;
  const tok = await tokenRequest({ token_endpoint: s.token_endpoint }, { grant_type: "refresh_token", refresh_token: s.refresh_token, client_id: s.client_id, resource: s.resource });
  save({ ...s, ...tok });
  return tok.access_token;
}

async function callTool(name, args) {
  const body = {
    jsonrpc: "2.0",
    id: Date.now(),
    method: "tools/call",
    params: { name, arguments: args, _meta: { "io.modelcontextprotocol/protocolVersion": VERSION, "io.modelcontextprotocol/clientInfo": { name: "archiehq-mcp-cli", version: "1.0.0" }, "io.modelcontextprotocol/clientCapabilities": {} } },
  };
  const r = await fetch(`${BASE}/mcp`, {
    method: "POST",
    headers: { authorization: `Bearer ${await accessToken()}`, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": VERSION, "mcp-method": "tools/call", "mcp-name": name },
    body: JSON.stringify(body),
  });
  const j = await r.json();
  if (j.error) throw new Error(`MCP error ${j.error.code}: ${j.error.message}`);
  if (j.result.isError) throw new Error(j.result.content?.map((c) => c.text).join(" ") || "tool error");
  return j.result.structuredContent ?? j.result.content;
}

const [cmd, ...rest] = process.argv.slice(2);
const flag = (n) => {
  const i = rest.indexOf(`--${n}`);
  return i >= 0 ? rest[i + 1] : undefined;
};
try {
  if (cmd === "login") await login();
  else if (cmd === "upload") {
    const path = rest[0];
    if (!path) throw new Error("usage: upload <path> [--name n] [--type t]");
    const buf = readFileSync(path);
    const isText = !buf.includes(0) && Buffer.from(buf.toString("utf8"), "utf8").equals(buf);
    const args = { filename: flag("name") || path.split(/[\\/]/).pop(), content: isText ? buf.toString("utf8") : buf.toString("base64"), encoding: isText ? "text" : "base64" };
    if (flag("type")) args.content_type = flag("type");
    console.log(JSON.stringify(await callTool("upload", args)));
  } else if (cmd === "call") console.log(JSON.stringify(await callTool(rest[0], JSON.parse(rest[1] || "{}"))));
  else console.log("commands: login | upload <path> [--name n] [--type t] | call <tool> '<json>'");
} catch (e) {
  console.error(String(e.message || e));
  process.exit(1);
}
