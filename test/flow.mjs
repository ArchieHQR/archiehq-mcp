// End-to-end check of the server as a stranger client would see it:
// discovery -> registration -> consent (passphrase) -> token -> MCP calls (modern and legacy).
// Usage: BASE=http://localhost:8787 PASSPHRASE=... AUDIO=path/to/clip.mp3 node test/flow.mjs
// Without PASSPHRASE it only runs the unauthenticated checks.

import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
const ajv = new Ajv2020({ strict: false });
addFormats(ajv);

const BASE = process.env.BASE || "http://localhost:8787";
const PASS = process.env.PASSPHRASE;
const AUDIO = process.env.AUDIO;
const b64url = (b) => Buffer.from(b).toString("base64url");
let failures = 0;
const check = (name, cond, extra = "") => {
  console.log(`${cond ? "PASS" : "FAIL"} ${name}${extra ? " — " + extra : ""}`);
  if (!cond) failures++;
};

// --- discovery
const r401 = await fetch(`${BASE}/mcp`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
const wa = r401.headers.get("www-authenticate") || "";
check("401 without token", r401.status === 401);
const prmUrl = wa.match(/resource_metadata="([^"]+)"/)?.[1];
check("WWW-Authenticate has resource_metadata", !!prmUrl, wa);
const prm = await (await fetch(prmUrl)).json();
check("PRM resource is /mcp", prm.resource === `${BASE}/mcp`);
check("PRM resource_documentation on same host", new URL(prm.resource_documentation).host === new URL(BASE).host);
const plan = await fetch(prm.resource_documentation);
check("plan page 200 html", plan.status === 200 && (plan.headers.get("content-type") || "").includes("text/html"));
const as = await (await fetch(`${prm.authorization_servers[0]}/.well-known/oauth-authorization-server`)).json();
check("AS issuer matches", as.issuer === prm.authorization_servers[0]);
check("AS supports S256", as.code_challenge_methods_supported?.includes("S256"));
check("AS CIMD flag", as.client_id_metadata_document_supported === true);
check("GET /mcp is 405", (await fetch(`${BASE}/mcp`)).status === 405);
const bad = await fetch(`${BASE}/mcp`, { method: "POST", headers: { authorization: "Bearer nope", "content-type": "application/json" }, body: "{}" });
check("bad token 401 invalid_token", bad.status === 401 && (bad.headers.get("www-authenticate") || "").includes('error="invalid_token"'));

if (!PASS) process.exit(failures ? 1 : 0);

// --- registration (DCR)
const redirect = "http://127.0.0.1:33418/callback";
const reg = await fetch(as.registration_endpoint, {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ client_name: "flow test", redirect_uris: [redirect], token_endpoint_auth_method: "none", application_type: "native", grant_types: ["authorization_code", "refresh_token"] }),
});
const client = await reg.json();
check("DCR 201", reg.status === 201, client.client_id);
const badReg = await fetch(as.registration_endpoint, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ redirect_uris: ["http://evil.example/cb"] }) });
check("DCR refuses non-loopback http redirect", badReg.status === 400);

// --- authorize
const verifier = b64url(randomBytes(32));
const challenge = b64url(createHash("sha256").update(verifier).digest());
const state = b64url(randomBytes(8));
const authUrl = new URL(as.authorization_endpoint);
Object.entries({ response_type: "code", client_id: client.client_id, redirect_uri: redirect, code_challenge: challenge, code_challenge_method: "S256", state, scope: "mcp", resource: prm.resource }).forEach(([k, v]) => authUrl.searchParams.set(k, v));
const consent = await fetch(authUrl, { redirect: "manual" });
const consentHtml = await consent.text();
const reqId = consentHtml.match(/name="request" value="([^"]+)"/)?.[1];
check("consent page shows", consent.status === 200 && !!reqId);
const plain = new URL(authUrl);
plain.searchParams.set("code_challenge_method", "plain");
const pr = await fetch(plain, { redirect: "manual" });
check("plain PKCE refused via redirect", pr.status === 302 && pr.headers.get("location").includes("error=invalid_request"));

const wrong = await fetch(as.authorization_endpoint, { method: "POST", body: new URLSearchParams({ request: reqId, passphrase: "wrong", decision: "allow" }), redirect: "manual" });
check("wrong passphrase refused", wrong.status === 401);
const ok = await fetch(as.authorization_endpoint, { method: "POST", body: new URLSearchParams({ request: reqId, passphrase: PASS, decision: "allow" }), redirect: "manual" });
const loc = new URL(ok.headers.get("location") || "http://x/");
check("approve redirects with code", ok.status === 302 && !!loc.searchParams.get("code"));
check("state echoed", loc.searchParams.get("state") === state);
check("iss in response", loc.searchParams.get("iss") === as.issuer);

// --- token
const tokRes = await fetch(as.token_endpoint, {
  method: "POST",
  body: new URLSearchParams({ grant_type: "authorization_code", code: loc.searchParams.get("code"), redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier, resource: prm.resource }),
});
const tok = await tokRes.json();
check("token issued", tokRes.status === 200 && !!tok.access_token && !!tok.refresh_token);
const reuse = await fetch(as.token_endpoint, { method: "POST", body: new URLSearchParams({ grant_type: "authorization_code", code: loc.searchParams.get("code"), redirect_uri: redirect, client_id: client.client_id, code_verifier: verifier }) });
check("code single use", reuse.status === 400);
const ref = await fetch(as.token_endpoint, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: client.client_id }) });
const tok2 = await ref.json();
check("refresh works", ref.status === 200 && !!tok2.access_token);
const ref2 = await fetch(as.token_endpoint, { method: "POST", body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: tok.refresh_token, client_id: client.client_id }) });
check("refresh token rotates", ref2.status === 400);
const AT = tok2.access_token;

// --- MCP (modern)
const V = "2026-07-28";
const meta = { "io.modelcontextprotocol/protocolVersion": V, "io.modelcontextprotocol/clientInfo": { name: "flow", version: "1" }, "io.modelcontextprotocol/clientCapabilities": {} };
let n = 0;
async function rpc(method, params = {}, { version = V, headers = {}, legacy = false } = {}) {
  const body = { jsonrpc: "2.0", id: ++n, method, params: legacy ? params : { ...params, _meta: meta } };
  const h = { authorization: `Bearer ${AT}`, "content-type": "application/json", accept: "application/json, text/event-stream", "mcp-protocol-version": version };
  if (!legacy) {
    h["mcp-method"] = method;
    if (params.name) h["mcp-name"] = params.name;
  }
  const r = await fetch(`${BASE}/mcp`, { method: "POST", headers: { ...h, ...headers }, body: JSON.stringify(body) });
  const out = { status: r.status, body: await r.json() };
  const res = out.body.result;
  if (method === "tools/call" && res && !res.isError && schemas[params.name]) {
    const ok = schemas[params.name](res.structuredContent);
    check(`  ${params.name} structuredContent matches outputSchema`, ok, ok ? "" : JSON.stringify(schemas[params.name].errors));
  }
  return out;
}
const disc = await rpc("server/discover");
check("server/discover", disc.status === 200 && disc.body.result?.supportedVersions?.includes(V) && disc.body.result.resultType === "complete");
const list = await rpc("tools/list");
const names = list.body.result?.tools?.map((t) => t.name) || [];
const schemas = {};
for (const t of list.body.result?.tools || []) {
  schemas[t.name] = ajv.compile(t.outputSchema);
  ajv.compile(t.inputSchema);
}
check("tools/list has 4 tools", ["memo_write", "memo_search", "upload", "transcribe"].every((x) => names.includes(x)), names.join(","));
check("tools/list cache fields", typeof list.body.result?.ttlMs === "number" && list.body.result?.cacheScope === "public");
const mism = await rpc("tools/list", {}, { headers: { "mcp-method": "tools/call" } });
check("Mcp-Method mismatch -> 400 -32020", mism.status === 400 && mism.body.error?.code === -32020);
const unsup = await rpc("tools/list", {}, { version: "1900-01-01" });
check("version header mismatch -> 400", unsup.status === 400);
const nf = await rpc("nope/nope");
check("unknown method -> 404 -32601", nf.status === 404 && nf.body.error?.code === -32601);

const text = `flow test note ${Date.now()}`;
const w = await rpc("tools/call", { name: "memo_write", arguments: { text } });
check("memo_write", w.body.result?.structuredContent?.id && !w.body.result.isError, JSON.stringify(w.body.result?.structuredContent));
const s = await rpc("tools/call", { name: "memo_search", arguments: { query: text.split(" ").slice(-1)[0] } });
check("memo_search finds it", s.body.result?.structuredContent?.notes?.[0]?.text === text);
const u = await rpc("tools/call", { name: "upload", arguments: { filename: "hello.txt", content: "hello world" } });
const fileUrl = u.body.result?.structuredContent?.url;
check("upload returns url", !!fileUrl, fileUrl);
const fr = await fetch(fileUrl);
check("upload link opens without auth", fr.status === 200 && (await fr.text()) === "hello world");
const badArgs = await rpc("tools/call", { name: "memo_write", arguments: { txt: "x" } });
check("bad args -> isError result", badArgs.body.result?.isError === true);
const unknown = await rpc("tools/call", { name: "nope", arguments: {} });
check("unknown tool -> -32602", unknown.body.error?.code === -32602);

if (AUDIO) {
  const up = await rpc("tools/call", { name: "upload", arguments: { filename: "clip.mp3", content: readFileSync(AUDIO).toString("base64"), encoding: "base64" } });
  const aurl = up.body.result?.structuredContent?.url;
  check("audio upload", !!aurl, aurl);
  const t = await rpc("tools/call", { name: "transcribe", arguments: { url: aurl } });
  const segs = t.body.result?.structuredContent?.segments || [];
  check("transcribe segments", segs.length > 0 && typeof segs[0].start === "number", JSON.stringify(segs.slice(0, 2)) || JSON.stringify(t.body).slice(0, 300));
}

if (process.env.TRANSCRIBE_URL) {
  const t = await rpc("tools/call", { name: "transcribe", arguments: { url: process.env.TRANSCRIBE_URL } });
  const segs = t.body.result?.structuredContent?.segments || [];
  check("transcribe external URL", segs.length > 0, JSON.stringify(segs.slice(0, 1)) || JSON.stringify(t.body).slice(0, 300));
}

// --- legacy client
const init = await fetch(`${BASE}/mcp`, {
  method: "POST",
  headers: { authorization: `Bearer ${AT}`, "content-type": "application/json", accept: "application/json, text/event-stream" },
  body: JSON.stringify({ jsonrpc: "2.0", id: 900, method: "initialize", params: { protocolVersion: "2025-11-25", capabilities: {}, clientInfo: { name: "legacy", version: "1" } } }),
});
const initBody = await init.json();
check("legacy initialize", initBody.result?.protocolVersion === "2025-11-25");
const lnote = await fetch(`${BASE}/mcp`, { method: "POST", headers: { authorization: `Bearer ${AT}`, "content-type": "application/json", "mcp-protocol-version": "2025-11-25" }, body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
check("legacy notification 202", lnote.status === 202);
const ll = await rpc("tools/list", {}, { version: "2025-11-25", legacy: true });
check("legacy tools/list", ll.body.result?.tools?.length === 4);
const lc = await rpc("tools/call", { name: "memo_search", arguments: { query: "flow" } }, { version: "2025-11-25", legacy: true });
check("legacy tools/call structuredContent", Array.isArray(lc.body.result?.structuredContent?.notes));

console.log(failures ? `\n${failures} FAILED` : "\nALL PASS");
process.exit(failures ? 1 : 0);
