// MCP endpoint over Streamable HTTP.
// Modern revision 2026-07-28 (stateless, per-request _meta, server/discover, header checks),
// plus the legacy revisions 2025-11-25 / 2025-06-18 / 2025-03-26 (initialize handshake, no session id).

import { json } from "./util.js";
import { TOOLS, callTool } from "./tools.js";
import { verifyBearer, urls, SCOPE } from "./oauth.js";

export const MODERN = ["2026-07-28"];
export const LEGACY = ["2025-11-25", "2025-06-18", "2025-03-26"];
const SUPPORTED = [...MODERN, ...LEGACY];
const LIST_TTL_MS = 300000;

const INSTRUCTIONS =
  "Archie's personal tool server. memo_write saves a note and memo_search finds notes (newest first). upload stores a file and returns a public link. transcribe turns audio at a URL into timestamped segments (seconds).";

function serverInfo(env) {
  return { name: env.SERVER_NAME, version: env.SERVER_VERSION };
}

function rpcError(id, code, message, data, status = 200) {
  const error = { code, message };
  if (data !== undefined) error.data = data;
  const body = { jsonrpc: "2.0", error };
  if (id !== undefined && id !== null) body.id = id;
  return json(body, status);
}

// Header values may carry the =?base64?...?= sentinel.
function decodeHeader(v) {
  if (v == null) return v;
  const m = v.match(/^=\?base64\?(.*)\?=$/);
  if (!m) return v;
  try {
    return new TextDecoder().decode(Uint8Array.from(atob(m[1]), (c) => c.charCodeAt(0)));
  } catch {
    return undefined;
  }
}

function allowedOrigin(origin, env) {
  if (!origin) return true;
  if (origin === "null") return false;
  try {
    const u = new URL(origin);
    if (u.protocol === "https:") return true; // remote web clients; requests still need a bearer token
    return u.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(u.hostname);
  } catch {
    return false;
  }
}

function unauthorized(env, error) {
  const u = urls(env);
  let h = `Bearer resource_metadata="${u.prm}", scope="${SCOPE}"`;
  if (error) h += `, error="${error}", error_description="The access token is missing, expired or not for this server"`;
  return json({ error: error || "unauthorized", error_description: "Sign in through this server's OAuth flow; see resource_metadata." }, 401, { "www-authenticate": h });
}

export async function handleMcp(request, env) {
  if (!allowedOrigin(request.headers.get("origin"), env)) return json({ jsonrpc: "2.0", error: { code: -32600, message: "Forbidden origin" } }, 403);
  if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });

  const auth = await verifyBearer(request, env);
  if (!auth.grant) return unauthorized(env, auth.present ? "invalid_token" : null);
  const grant = auth.grant;

  let msg;
  try {
    msg = await request.json();
  } catch {
    return rpcError(null, -32700, "Parse error: body must be one JSON-RPC message", undefined, 400);
  }
  if (Array.isArray(msg)) return rpcError(null, -32600, "Invalid Request: batches are not supported", undefined, 400);
  if (!msg || msg.jsonrpc !== "2.0" || typeof msg.method !== "string") return rpcError(msg?.id, -32600, "Invalid Request", undefined, 400);

  const isNotification = !("id" in msg);
  if (isNotification) return new Response(null, { status: 202 });
  const { id, method } = msg;
  if (id === null || (typeof id !== "string" && typeof id !== "number")) return rpcError(null, -32600, "Invalid Request: id must be a string or number", undefined, 400);
  const params = msg.params && typeof msg.params === "object" ? msg.params : {};
  const meta = params._meta && typeof params._meta === "object" ? params._meta : {};

  const headerVersion = request.headers.get("mcp-protocol-version");
  const metaVersion = meta["io.modelcontextprotocol/protocolVersion"];

  // Legacy handshake.
  if (method === "initialize" && metaVersion === undefined) return initialize(id, params, env);

  const version = metaVersion ?? headerVersion ?? "2025-03-26";
  if (!SUPPORTED.includes(version)) {
    return rpcError(id, -32022, "Unsupported protocol version", { supported: SUPPORTED, requested: version }, 400);
  }

  if (MODERN.includes(version)) {
    // Header/body validation (Streamable HTTP, 2026-07-28).
    if (metaVersion === undefined) return rpcError(id, -32602, "Invalid params: _meta io.modelcontextprotocol/protocolVersion is required", undefined, 400);
    if (!meta["io.modelcontextprotocol/clientCapabilities"] || typeof meta["io.modelcontextprotocol/clientCapabilities"] !== "object")
      return rpcError(id, -32602, "Invalid params: _meta io.modelcontextprotocol/clientCapabilities is required", undefined, 400);
    if (headerVersion !== metaVersion) return rpcError(id, -32020, `Header mismatch: MCP-Protocol-Version '${headerVersion ?? ""}' does not match body '${metaVersion}'`, undefined, 400);
    const hMethod = request.headers.get("mcp-method");
    if (hMethod !== method) return rpcError(id, -32020, `Header mismatch: Mcp-Method '${hMethod ?? ""}' does not match body '${method}'`, undefined, 400);
    if (["tools/call", "resources/read", "prompts/get"].includes(method)) {
      const raw = request.headers.get("mcp-name");
      const hName = decodeHeader(raw);
      const bName = params.name ?? params.uri;
      if (hName === undefined || hName !== bName) return rpcError(id, -32020, `Header mismatch: Mcp-Name '${raw ?? ""}' does not match body '${bName ?? ""}'`, undefined, 400);
    }
    return modern(id, method, params, env, grant);
  }
  return legacy(id, method, params, env, grant, version);
}

function withMeta(result, env) {
  return { resultType: "complete", ...result, _meta: { "io.modelcontextprotocol/serverInfo": serverInfo(env) } };
}

async function modern(id, method, params, env, grant) {
  const ok = (result) => json({ jsonrpc: "2.0", id, result: withMeta(result, env) });
  switch (method) {
    case "server/discover":
      return ok({ supportedVersions: SUPPORTED, capabilities: { tools: { listChanged: false } }, instructions: INSTRUCTIONS, ttlMs: LIST_TTL_MS, cacheScope: "public" });
    case "tools/list":
      return ok({ tools: TOOLS, ttlMs: LIST_TTL_MS, cacheScope: "public" });
    case "tools/call": {
      const res = await runTool(id, params, env, grant, 400);
      return res instanceof Response ? res : ok(res);
    }
    case "initialize":
      return rpcError(id, -32601, `initialize is not part of protocol ${MODERN[0]}; send requests with per-request _meta`, { supported: SUPPORTED }, 404);
    default:
      return rpcError(id, -32601, `Method not found: ${method}`, undefined, 404);
  }
}

async function legacy(id, method, params, env, grant, version) {
  const ok = (result) => json({ jsonrpc: "2.0", id, result });
  switch (method) {
    case "ping":
      return ok({});
    case "tools/list": {
      // outputSchema arrived in 2025-06-18; annotations/title are harmless extras.
      const tools = version === "2025-03-26" ? TOOLS.map(({ outputSchema, ...t }) => t) : TOOLS;
      return ok({ tools });
    }
    case "tools/call": {
      const res = await runTool(id, params, env, grant, 200);
      if (res instanceof Response) return res;
      if (version === "2025-03-26" && res.structuredContent) {
        // No structuredContent before 2025-06-18: the JSON goes in the text block instead.
        res.content = [{ type: "text", text: JSON.stringify(res.structuredContent) }];
        delete res.structuredContent;
      }
      return ok(res);
    }
    case "server/discover":
      return modern(id, method, params, env, grant);
    case "logging/setLevel":
      return ok({});
    default:
      return rpcError(id, -32601, `Method not found: ${method}`);
  }
}

async function runTool(id, params, env, grant, errStatus) {
  if (typeof params.name !== "string") return rpcError(id, -32602, "Invalid params: name is required", undefined, errStatus);
  if (env.TOOL_LIMIT && !(await env.TOOL_LIMIT.limit({ key: grant.client_id })).success)
    return { content: [{ type: "text", text: "Rate limit: at most 60 tool calls per minute. Wait and retry." }], isError: true };
  if (params.arguments !== undefined && (params.arguments === null || typeof params.arguments !== "object" || Array.isArray(params.arguments)))
    return rpcError(id, -32602, "Invalid params: arguments must be an object", undefined, errStatus);
  const res = await callTool(params.name, params.arguments ?? {}, { env, grant });
  if (!res) return rpcError(id, -32602, `Unknown tool: ${params.name}`, undefined, errStatus);
  return res;
}

function initialize(id, params, env) {
  const asked = params.protocolVersion;
  const version = LEGACY.includes(asked) ? asked : LEGACY[0];
  return json({
    jsonrpc: "2.0",
    id,
    result: {
      protocolVersion: version,
      capabilities: { tools: { listChanged: false } },
      serverInfo: serverInfo(env),
      instructions: INSTRUCTIONS,
    },
  });
}
