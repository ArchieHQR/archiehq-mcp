// OAuth 2.1 authorization server for this MCP server (same host).
// - Client registration: Client ID Metadata Documents (preferred) and Dynamic Client Registration (RFC 7591).
// - Authorization code + PKCE (S256 only), RFC 8707 resource binding, RFC 9207 `iss` in responses.
// - The owner lets a client in on the consent page with the owner passphrase (secret OWNER_PASSPHRASE).
// - Tokens are opaque; KV stores only their SHA-256 hash.

import { json, html, esc, randomToken, sha256, sha256hex, base64url, safeEqual, publicUrl, limitedFetch, LOOPBACK_HOSTS } from "./util.js";

export const SCOPE = "mcp";
const ACCESS_TTL = 3600; // 1 hour
const REFRESH_TTL = 30 * 24 * 3600; // 30 days
const CODE_TTL = 300; // 5 minutes
const REQUEST_TTL = 900; // consent page lifetime: 15 minutes

export function urls(env) {
  const o = env.ORIGIN;
  return {
    issuer: o,
    resource: `${o}/mcp`,
    prm: `${o}/.well-known/oauth-protected-resource`,
    plan: `${o}/plan`,
  };
}

// RFC 9728 protected resource metadata
export function protectedResourceMetadata(env) {
  const u = urls(env);
  return {
    resource: u.resource,
    authorization_servers: [u.issuer],
    scopes_supported: [SCOPE],
    bearer_methods_supported: ["header"],
    resource_name: "Archie's MCP server (memo, upload, transcribe)",
    resource_documentation: u.plan,
  };
}

// RFC 8414 authorization server metadata
export function authorizationServerMetadata(env) {
  const o = env.ORIGIN;
  return {
    issuer: o,
    authorization_endpoint: `${o}/authorize`,
    token_endpoint: `${o}/token`,
    registration_endpoint: `${o}/register`,
    revocation_endpoint: `${o}/revoke`,
    scopes_supported: [SCOPE],
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    revocation_endpoint_auth_methods_supported: ["none", "client_secret_basic", "client_secret_post"],
    code_challenge_methods_supported: ["S256"],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
    service_documentation: `${o}/plan`,
  };
}

function oauthError(error, description, status = 400) {
  return json({ error, error_description: description }, status, { "cache-control": "no-store" });
}

// ---------- redirect URIs ----------

const BAD_SCHEMES = new Set(["javascript:", "data:", "file:", "vbscript:", "about:", "blob:", "ftp:", "ws:", "wss:"]);

function redirectUriOk(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return false;
  }
  if (u.hash) return false;
  if (u.protocol === "https:") return true;
  if (u.protocol === "http:") return LOOPBACK_HOSTS.has(u.hostname);
  return !BAD_SCHEMES.has(u.protocol); // private-use scheme of a native app
}

// Exact match; for http loopback redirects the port may differ (RFC 8252 section 7.3).
function redirectMatches(registered, requested) {
  if (registered === requested) return true;
  try {
    const a = new URL(registered);
    const b = new URL(requested);
    return a.protocol === "http:" && b.protocol === "http:" && LOOPBACK_HOSTS.has(a.hostname) && a.hostname === b.hostname && a.pathname === b.pathname && a.search === b.search;
  } catch {
    return false;
  }
}

// ---------- clients ----------

async function loadClient(env, clientId) {
  if (!clientId) return { error: "client_id is missing" };
  if (clientId.startsWith("https://")) return loadMetadataDocumentClient(clientId);
  const stored = await env.OAUTH.get(`client:${clientId}`, "json");
  return stored ? { client: stored } : { error: "unknown client_id" };
}

async function loadMetadataDocumentClient(clientId) {
  const u = publicUrl(clientId, { httpsOnly: true });
  if (!u || u.pathname === "/" || u.hash) return { error: "client_id URL must be a public https URL with a path" };
  let doc;
  try {
    const { bytes } = await limitedFetch(u.toString(), { maxBytes: 10240, timeoutMs: 5000, accept: "application/json" });
    doc = JSON.parse(new TextDecoder().decode(bytes));
  } catch (e) {
    return { error: `could not read the client metadata document: ${e.message}` };
  }
  if (!doc || typeof doc !== "object") return { error: "client metadata document is not a JSON object" };
  if (doc.client_id !== clientId) return { error: "client metadata document client_id does not match its URL" };
  if (!Array.isArray(doc.redirect_uris) || !doc.redirect_uris.length || !doc.redirect_uris.every((r) => typeof r === "string" && redirectUriOk(r)))
    return { error: "client metadata document has no valid redirect_uris" };
  const method = doc.token_endpoint_auth_method || "none";
  if (method !== "none") return { error: "only public clients (token_endpoint_auth_method none) are supported for metadata document clients" };
  return {
    client: {
      client_id: clientId,
      client_name: typeof doc.client_name === "string" ? doc.client_name.slice(0, 100) : u.host,
      redirect_uris: doc.redirect_uris,
      token_endpoint_auth_method: "none",
      kind: "cimd",
    },
  };
}

export async function register(request, env) {
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.AUTH_LIMIT && !(await env.AUTH_LIMIT.limit({ key: `register:${ip}` })).success) return oauthError("slow_down", "too many registrations; wait a minute", 429);
  let meta;
  try {
    meta = await request.json();
  } catch {
    return oauthError("invalid_client_metadata", "body must be JSON");
  }
  const redirect_uris = meta?.redirect_uris;
  if (!Array.isArray(redirect_uris) || !redirect_uris.length || redirect_uris.length > 10) return oauthError("invalid_redirect_uri", "redirect_uris must be a non-empty array (at most 10)");
  for (const r of redirect_uris) if (typeof r !== "string" || !redirectUriOk(r)) return oauthError("invalid_redirect_uri", `redirect URI not allowed: ${String(r).slice(0, 200)}`);
  const method = meta.token_endpoint_auth_method || "none";
  if (!["none", "client_secret_basic", "client_secret_post"].includes(method)) return oauthError("invalid_client_metadata", "unsupported token_endpoint_auth_method");
  const grant_types = meta.grant_types || ["authorization_code", "refresh_token"];
  if (!Array.isArray(grant_types) || grant_types.some((g) => !["authorization_code", "refresh_token"].includes(g))) return oauthError("invalid_client_metadata", "unsupported grant_types");
  const response_types = meta.response_types || ["code"];
  if (!Array.isArray(response_types) || response_types.some((t) => t !== "code")) return oauthError("invalid_client_metadata", "only response_type code is supported");

  const client = {
    client_id: `c_${randomToken(16)}`,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: typeof meta.client_name === "string" ? meta.client_name.slice(0, 100) : "unnamed client",
    redirect_uris,
    grant_types,
    response_types,
    token_endpoint_auth_method: method,
    application_type: meta.application_type === "native" ? "native" : "web",
    scope: SCOPE,
    kind: "dcr",
  };
  if (typeof meta.client_uri === "string") client.client_uri = meta.client_uri.slice(0, 300);
  const out = { ...client };
  delete out.kind;
  if (method !== "none") {
    const secret = randomToken(32);
    client.secret_hash = await sha256hex(secret);
    out.client_secret = secret;
    out.client_secret_expires_at = 0;
  }
  await env.OAUTH.put(`client:${client.client_id}`, JSON.stringify(client));
  return json(out, 201, { "cache-control": "no-store" });
}

// ---------- /authorize ----------

function errorPage(title, detail, status = 400) {
  return html(page(title, `<p>${esc(detail)}</p>`), status);
}

function redirectWith(redirectUri, params, env) {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null) u.searchParams.set(k, v);
  u.searchParams.set("iss", env.ORIGIN);
  return new Response(null, { status: 302, headers: { location: u.toString(), "cache-control": "no-store", "referrer-policy": "no-referrer" } });
}

function resourceOk(resource, env) {
  if (!resource) return true;
  const u = urls(env);
  const r = resource.replace(/\/+$/, "");
  return r.toLowerCase() === u.resource.toLowerCase() || r.toLowerCase() === u.issuer.toLowerCase();
}

export async function authorizeGet(request, env) {
  const p = new URL(request.url).searchParams;
  const clientId = p.get("client_id");
  const redirectUri = p.get("redirect_uri");
  const { client, error } = await loadClient(env, clientId);
  if (!client) return errorPage("Sign-in request refused", error);
  let redirect = redirectUri;
  if (!redirect) {
    if (client.redirect_uris.length !== 1) return errorPage("Sign-in request refused", "redirect_uri is missing");
    redirect = client.redirect_uris[0];
  }
  if (!client.redirect_uris.some((r) => redirectMatches(r, redirect))) return errorPage("Sign-in request refused", "redirect_uri is not registered for this client");

  const state = p.get("state") ?? undefined;
  const fail = (err, desc) => redirectWith(redirect, { error: err, error_description: desc, state }, env);
  if (p.get("response_type") !== "code") return fail("unsupported_response_type", "response_type must be code");
  const challenge = p.get("code_challenge");
  if (!challenge || !/^[A-Za-z0-9\-._~]{43,128}$/.test(challenge)) return fail("invalid_request", "a PKCE code_challenge is required");
  if ((p.get("code_challenge_method") || "plain") !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
  const resource = p.get("resource") || "";
  if (!resourceOk(resource, env)) return fail("invalid_target", "resource must be this MCP server");

  const id = randomToken(24);
  const req = {
    client_id: client.client_id,
    client_name: client.client_name,
    kind: client.kind,
    redirect_uri: redirect,
    redirect_uri_given: !!redirectUri,
    state,
    code_challenge: challenge,
    scope: SCOPE,
    resource: urls(env).resource,
    tries: 0,
  };
  await env.OAUTH.put(`req:${id}`, JSON.stringify(req), { expirationTtl: REQUEST_TTL });
  return html(consentPage(id, req, env));
}

export async function authorizePost(request, env) {
  const form = await request.formData();
  const id = String(form.get("request") || "");
  const req = id && (await env.OAUTH.get(`req:${id}`, "json"));
  if (!req) return errorPage("Sign-in request expired", "Start the connection again from the app.");
  if (form.get("decision") === "deny") {
    await env.OAUTH.delete(`req:${id}`);
    return redirectWith(req.redirect_uri, { error: "access_denied", error_description: "the owner denied access", state: req.state }, env);
  }
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  if (env.AUTH_LIMIT && !(await env.AUTH_LIMIT.limit({ key: `pass:${ip}` })).success) return html(consentPage(id, req, env, "Too many tries. Wait a minute and try again."), 429);
  if (!env.OWNER_PASSPHRASE) return errorPage("Server not ready", "The owner passphrase is not set yet.", 503);
  const ok = await safeEqual(String(form.get("passphrase") || ""), env.OWNER_PASSPHRASE);
  if (!ok) {
    req.tries++;
    if (req.tries >= 5) {
      await env.OAUTH.delete(`req:${id}`);
      return redirectWith(req.redirect_uri, { error: "access_denied", error_description: "too many wrong passphrases", state: req.state }, env);
    }
    await env.OAUTH.put(`req:${id}`, JSON.stringify(req), { expirationTtl: REQUEST_TTL });
    return html(consentPage(id, req, env, "Wrong passphrase."), 401);
  }
  await env.OAUTH.delete(`req:${id}`);
  const code = randomToken(32);
  const grant = {
    client_id: req.client_id,
    client_name: req.client_name,
    redirect_uri: req.redirect_uri,
    redirect_uri_given: req.redirect_uri_given,
    code_challenge: req.code_challenge,
    scope: req.scope,
    resource: req.resource,
    approved_at: new Date().toISOString(),
  };
  await env.OAUTH.put(`code:${await sha256hex(code)}`, JSON.stringify(grant), { expirationTtl: CODE_TTL });
  return redirectWith(req.redirect_uri, { code, state: req.state }, env);
}

// ---------- /token ----------

async function readParams(request) {
  const type = request.headers.get("content-type") || "";
  if (type.includes("application/json")) {
    const j = await request.json().catch(() => ({}));
    return new Map(Object.entries(j).map(([k, v]) => [k, String(v)]));
  }
  const text = await request.text();
  return new Map(new URLSearchParams(text));
}

async function authenticateClient(request, params, env) {
  let id = params.get("client_id");
  let secret = params.get("client_secret");
  const auth = request.headers.get("authorization") || "";
  if (auth.toLowerCase().startsWith("basic ")) {
    try {
      const [u, s] = atob(auth.slice(6).trim()).split(":");
      id = decodeURIComponent(u);
      secret = decodeURIComponent(s ?? "");
    } catch {
      return { error: oauthError("invalid_client", "bad basic auth header", 401) };
    }
  }
  if (!id) return { error: oauthError("invalid_client", "client_id is missing", 401) };
  if (id.startsWith("https://")) return { clientId: id, client: { client_id: id, token_endpoint_auth_method: "none" } };
  const client = await env.OAUTH.get(`client:${id}`, "json");
  if (!client) return { error: oauthError("invalid_client", "unknown client", 401) };
  if (client.token_endpoint_auth_method !== "none") {
    if (!secret || !(await safeEqual(await sha256hex(secret), client.secret_hash))) return { error: oauthError("invalid_client", "client authentication failed", 401) };
  }
  return { clientId: id, client };
}

async function issueTokens(env, grant) {
  const access = randomToken(32);
  const refresh = randomToken(32);
  const base = { client_id: grant.client_id, client_name: grant.client_name, scope: grant.scope, resource: grant.resource };
  await env.OAUTH.put(`at:${await sha256hex(access)}`, JSON.stringify({ ...base, exp: Date.now() + ACCESS_TTL * 1000 }), { expirationTtl: ACCESS_TTL });
  await env.OAUTH.put(`rt:${await sha256hex(refresh)}`, JSON.stringify(base), { expirationTtl: REFRESH_TTL });
  return json({ access_token: access, token_type: "Bearer", expires_in: ACCESS_TTL, refresh_token: refresh, scope: grant.scope }, 200, { "cache-control": "no-store", pragma: "no-cache" });
}

export async function token(request, env) {
  const params = await readParams(request);
  const { clientId, error } = await authenticateClient(request, params, env);
  if (error) return error;
  const grantType = params.get("grant_type");
  const resource = params.get("resource");
  if (resource && !resourceOk(resource, env)) return oauthError("invalid_target", "resource must be this MCP server");

  if (grantType === "authorization_code") {
    const code = params.get("code") || "";
    const key = `code:${await sha256hex(code)}`;
    const grant = code && (await env.OAUTH.get(key, "json"));
    if (!grant) return oauthError("invalid_grant", "code is invalid, expired or already used");
    await env.OAUTH.delete(key); // single use
    if (grant.client_id !== clientId) return oauthError("invalid_grant", "code was issued to another client");
    const redirect = params.get("redirect_uri");
    if (grant.redirect_uri_given && redirect !== grant.redirect_uri) return oauthError("invalid_grant", "redirect_uri does not match the authorization request");
    const verifier = params.get("code_verifier") || "";
    if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) return oauthError("invalid_grant", "code_verifier is missing or malformed");
    if (base64url(await sha256(verifier)) !== grant.code_challenge) return oauthError("invalid_grant", "PKCE verification failed");
    return issueTokens(env, grant);
  }

  if (grantType === "refresh_token") {
    const rt = params.get("refresh_token") || "";
    const key = `rt:${await sha256hex(rt)}`;
    const grant = rt && (await env.OAUTH.get(key, "json"));
    if (!grant) return oauthError("invalid_grant", "refresh token is invalid or expired");
    if (grant.client_id !== clientId) return oauthError("invalid_grant", "refresh token was issued to another client");
    await env.OAUTH.delete(key); // rotation: each refresh token works once
    return issueTokens(env, grant);
  }

  return oauthError("unsupported_grant_type", "grant_type must be authorization_code or refresh_token");
}

export async function revoke(request, env) {
  const params = await readParams(request);
  const t = params.get("token") || "";
  if (t) {
    const h = await sha256hex(t);
    await Promise.all([env.OAUTH.delete(`at:${h}`), env.OAUTH.delete(`rt:${h}`)]);
  }
  return new Response(null, { status: 200 });
}

// Returns the grant behind a bearer token, or null.
export async function verifyBearer(request, env) {
  const auth = request.headers.get("authorization") || "";
  const m = auth.match(/^Bearer\s+([A-Za-z0-9\-._~+/]+=*)\s*$/i);
  if (!m) return { present: !!auth };
  const grant = await env.OAUTH.get(`at:${await sha256hex(m[1])}`, "json");
  if (!grant || grant.exp < Date.now() || grant.resource !== urls(env).resource) return { present: true };
  return { present: true, grant };
}

// ---------- pages ----------

export function page(title, body) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--muted:#5d5d58;--card:#fff;--line:#deded8;--accent:#1f5fbf;--warn:#9a5b00}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ececea;--muted:#a3a39d;--card:#20201f;--line:#34342f;--accent:#7fb0ff;--warn:#f0b35a}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:720px;margin:0 auto;padding:32px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:20px 22px;margin:16px 0}
h1{font-size:1.5rem;margin:0 0 8px}h2{font-size:1.15rem;margin:28px 0 8px}
code{font:14px ui-monospace,Consolas,monospace;background:color-mix(in srgb,var(--line) 45%,transparent);padding:1px 4px;border-radius:4px;word-break:break-all}
.muted{color:var(--muted)}.warn{color:var(--warn)}
input[type=password]{width:100%;box-sizing:border-box;padding:10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);font-size:16px}
button{padding:10px 18px;border-radius:6px;border:1px solid var(--line);font-size:15px;cursor:pointer;background:var(--card);color:var(--fg)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
</style></head><body><main>${body}</main></body></html>`;
}

function consentPage(id, req, env, message = "") {
  let host = req.redirect_uri;
  let loopback = false;
  try {
    const u = new URL(req.redirect_uri);
    host = u.protocol === "http:" || u.protocol === "https:" ? u.host : u.protocol;
    loopback = LOOPBACK_HOSTS.has(u.hostname);
  } catch {}
  return page(
    "Let this app in?",
    `<h1>Let this app use the MCP server?</h1>
<p class="muted">${esc(env.ORIGIN)}/mcp · tools: memo_write, memo_search, upload, transcribe</p>
<div class="card">
<table>
<tr><th>App name</th><td>${esc(req.client_name)} <span class="muted">(self-reported)</span></td></tr>
<tr><th>Client ID</th><td><code>${esc(req.client_id)}</code></td></tr>
<tr><th>Sends you back to</th><td><code>${esc(host)}</code>${loopback ? ' <span class="warn">— a program on the computer that started this sign-in</span>' : ""}</td></tr>
<tr><th>Access</th><td>All four tools: read and write notes, upload files, transcribe audio. Valid 1 hour, renewable for 30 days.</td></tr>
</table>
</div>
${message ? `<p class="warn"><strong>${esc(message)}</strong></p>` : ""}
<form method="post" action="/authorize" class="card">
<input type="hidden" name="request" value="${esc(id)}">
<label for="pp"><strong>Owner passphrase</strong></label>
<p class="muted" style="margin:4px 0 8px">Only the owner of this server knows it.</p>
<input id="pp" type="password" name="passphrase" autocomplete="current-password" autofocus>
<p style="display:flex;gap:10px;margin:16px 0 0"><button class="primary" type="submit" name="decision" value="allow">Allow</button>
<button type="submit" name="decision" value="deny">Deny</button></p>
</form>
<p class="muted">What this server does and keeps: <a href="/plan" style="color:var(--accent)">plan page</a>.</p>`,
  );
}
