// The four tools: memo_write, memo_search, upload, transcribe.
// Each tool declares an inputSchema and an outputSchema; a successful call returns
// structuredContent that matches the outputSchema, plus the same JSON as text.

import { randomToken, nowIso, publicUrl, limitedFetch, bytesToBase64, base64ToBytes } from "./util.js";

const MAX_NOTE = 20000;
const MAX_UPLOAD = 10 * 1024 * 1024; // 10 MB
const MAX_AUDIO = 25 * 1024 * 1024; // 25 MB

export const TOOLS = [
  {
    name: "memo_write",
    title: "Save a note",
    description: "Saves a text note on this server and returns its id. Notes are shared by everyone the owner lets in.",
    inputSchema: {
      type: "object",
      properties: { text: { type: "string", minLength: 1, maxLength: MAX_NOTE, description: "The note text." } },
      required: ["text"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        id: { type: "string", description: "Id of the saved note." },
        created_at: { type: "string", format: "date-time" },
      },
      required: ["id", "created_at"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false },
  },
  {
    name: "memo_search",
    title: "Find notes",
    description:
      "Finds saved notes whose text contains every word of the query (case-insensitive), newest first. An empty query returns the newest notes.",
    inputSchema: {
      type: "object",
      properties: {
        query: { type: "string", maxLength: 500, description: "Words to look for. Empty string = newest notes." },
        limit: { type: "integer", minimum: 1, maximum: 50, default: 20, description: "Maximum number of notes to return." },
      },
      required: ["query"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        notes: {
          type: "array",
          items: {
            type: "object",
            properties: {
              id: { type: "string" },
              text: { type: "string" },
              created_at: { type: "string", format: "date-time" },
              author: { type: "string", description: "Name of the app that saved the note." },
            },
            required: ["id", "text", "created_at"],
          },
        },
      },
      required: ["notes"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "upload",
    title: "Upload a file",
    description:
      "Stores a file on this server and returns a public link that anyone can open. Send text as is (encoding \"text\") or binary data as base64 (encoding \"base64\"). Limit 10 MB.",
    inputSchema: {
      type: "object",
      properties: {
        content: { type: "string", description: "The file content: plain text, or base64 when encoding is \"base64\"." },
        filename: { type: "string", maxLength: 200, description: "File name, e.g. notes.txt or clip.mp3. Default: file.txt or file.bin." },
        encoding: { type: "string", enum: ["text", "base64"], default: "text", description: "How content is encoded." },
        content_type: { type: "string", maxLength: 100, description: "MIME type. Default: guessed from the file name." },
      },
      required: ["content"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        url: { type: "string", format: "uri", description: "Public link to the file, served by this server." },
        id: { type: "string" },
        filename: { type: "string" },
        content_type: { type: "string" },
        size: { type: "integer", description: "Size in bytes." },
      },
      required: ["url", "id", "filename", "content_type", "size"],
    },
    annotations: { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: true },
  },
  {
    name: "transcribe",
    title: "Transcribe audio",
    description:
      "Downloads audio (mp3, wav, m4a, ogg, webm, flac; up to 25 MB) from a public http(s) URL and turns speech into timestamped text with Whisper. start and end are seconds from the beginning of the audio.",
    inputSchema: {
      type: "object",
      properties: {
        url: { type: "string", format: "uri", description: "Public URL of the audio file." },
        language: { type: "string", pattern: "^[a-z]{2}$", description: "Optional ISO 639-1 language code, e.g. en. Default: detected." },
      },
      required: ["url"],
      additionalProperties: false,
    },
    outputSchema: {
      type: "object",
      properties: {
        segments: {
          type: "array",
          items: {
            type: "object",
            properties: {
              start: { type: "number", minimum: 0, description: "Start in seconds." },
              end: { type: "number", minimum: 0, description: "End in seconds." },
              text: { type: "string" },
            },
            required: ["start", "end", "text"],
          },
        },
        text: { type: "string", description: "The whole transcript." },
        language: { type: "string" },
        duration: { type: "number", description: "Audio length in seconds." },
      },
      required: ["segments", "text"],
    },
    annotations: { readOnlyHint: true, openWorldHint: true },
  },
];

const TYPES = {
  txt: "text/plain; charset=utf-8", md: "text/markdown; charset=utf-8", csv: "text/csv; charset=utf-8", json: "application/json",
  html: "text/html; charset=utf-8", htm: "text/html; charset=utf-8", xml: "application/xml", pdf: "application/pdf",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif", webp: "image/webp", svg: "image/svg+xml",
  mp3: "audio/mpeg", wav: "audio/wav", m4a: "audio/mp4", ogg: "audio/ogg", oga: "audio/ogg", opus: "audio/ogg", flac: "audio/flac", webm: "audio/webm",
  mp4: "video/mp4", zip: "application/zip",
};

// Argument checks for the input schemas above. Returns an error message or null.
function check(tool, args) {
  if (args === null || typeof args !== "object" || Array.isArray(args)) return "arguments must be an object";
  const props = tool.inputSchema.properties;
  for (const k of Object.keys(args)) if (!(k in props)) return `unknown argument "${k}"; allowed: ${Object.keys(props).join(", ")}`;
  for (const k of tool.inputSchema.required) if (args[k] === undefined || args[k] === null) return `argument "${k}" is required`;
  for (const [k, v] of Object.entries(args)) {
    const s = props[k];
    if (v === undefined || v === null) continue;
    if (s.type === "string") {
      if (typeof v !== "string") return `"${k}" must be a string`;
      if (s.minLength && v.length < s.minLength) return `"${k}" must not be empty`;
      if (s.maxLength && v.length > s.maxLength) return `"${k}" is longer than ${s.maxLength} characters`;
      if (s.enum && !s.enum.includes(v)) return `"${k}" must be one of: ${s.enum.join(", ")}`;
      if (s.pattern && !new RegExp(s.pattern).test(v)) return `"${k}" has the wrong format`;
    }
    if (s.type === "integer") {
      if (!Number.isInteger(v)) return `"${k}" must be an integer`;
      if (v < s.minimum || v > s.maximum) return `"${k}" must be between ${s.minimum} and ${s.maximum}`;
    }
  }
  return null;
}

class ToolError extends Error {}

export async function callTool(name, args, ctx) {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return null; // caller turns this into a protocol error
  const problem = check(tool, args ?? {});
  if (problem) return errorResult(`Invalid arguments for ${name}: ${problem}.`);
  try {
    const out = await HANDLERS[name](args ?? {}, ctx);
    return { content: [{ type: "text", text: JSON.stringify(out) }], structuredContent: out, isError: false };
  } catch (e) {
    if (e instanceof ToolError) return errorResult(e.message);
    console.error("tool failed", name, e?.stack || e);
    return errorResult(`${name} failed: ${e?.message || "internal error"}`);
  }
}

function errorResult(text) {
  return { content: [{ type: "text", text }], isError: true };
}

const HANDLERS = {
  async memo_write({ text }, { env, grant }) {
    const id = `note_${Date.now().toString(36)}_${randomToken(6)}`;
    const created_at = nowIso();
    await env.DB.prepare("INSERT INTO notes (id, text, created_at, client_id, client_name) VALUES (?, ?, ?, ?, ?)")
      .bind(id, text, created_at, grant.client_id, grant.client_name || "")
      .run();
    return { id, created_at };
  },

  async memo_search({ query, limit = 20 }, { env }) {
    const terms = query.trim().split(/\s+/).filter(Boolean).slice(0, 10);
    const where = terms.map(() => "(lower(text) LIKE ? ESCAPE '\\' OR id = ?)").join(" AND ");
    const binds = terms.flatMap((t) => [`%${t.toLowerCase().replace(/[\\%_]/g, (c) => "\\" + c)}%`, t]);
    const sql = `SELECT id, text, created_at, client_name FROM notes ${where ? "WHERE " + where : ""} ORDER BY created_at DESC, id DESC LIMIT ?`;
    const { results } = await env.DB.prepare(sql).bind(...binds, limit).all();
    return { notes: results.map((r) => ({ id: r.id, text: r.text, created_at: r.created_at, author: r.client_name || "" })) };
  },

  async upload({ content, filename, encoding = "text", content_type }, { env, grant }) {
    let bytes;
    if (encoding === "base64") {
      try {
        bytes = base64ToBytes(content);
      } catch {
        throw new ToolError("content is not valid base64.");
      }
    } else bytes = new TextEncoder().encode(content);
    if (bytes.byteLength > MAX_UPLOAD) throw new ToolError(`The file is ${bytes.byteLength} bytes; the limit is ${MAX_UPLOAD}.`);
    const clean = (filename || (encoding === "base64" ? "file.bin" : "file.txt")).replace(/[\\/]/g, "_").replace(/[^\w.\- ]+/g, "_").replace(/\s+/g, "-").replace(/^\.+/, "").slice(0, 120) || "file";
    const ext = clean.includes(".") ? clean.split(".").pop().toLowerCase() : "";
    const type = (content_type && /^[\w.+-]+\/[\w.+-]+(;\s*[\w-]+=[\w.-]+)?$/.test(content_type) ? content_type : null) || TYPES[ext] || (encoding === "text" ? "text/plain; charset=utf-8" : "application/octet-stream");
    const id = `f_${Date.now().toString(36)}${randomToken(9)}`;
    await env.FILES.put(id, bytes, { httpMetadata: { contentType: type }, customMetadata: { filename: clean, client_id: grant.client_id } });
    await env.DB.prepare("INSERT INTO files (id, filename, content_type, size, created_at, client_id) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(id, clean, type, bytes.byteLength, nowIso(), grant.client_id)
      .run();
    return { url: `${env.ORIGIN}/f/${id}/${encodeURIComponent(clean)}`, id, filename: clean, content_type: type, size: bytes.byteLength };
  },

  async transcribe({ url, language }, { env }) {
    const bytes = await loadAudio(url, env);
    if (bytes.byteLength < 100) throw new ToolError("The file at that URL is too small to be audio.");
    const input = { audio: bytesToBase64(bytes), task: "transcribe", vad_filter: false };
    if (language) input.language = language;
    let out;
    try {
      out = await env.AI.run(env.WHISPER_MODEL, input);
    } catch (e) {
      throw new ToolError(`Speech recognition failed: ${e.message}. Check that the URL is an audio file.`);
    }
    const round = (n) => Math.round(Number(n || 0) * 1000) / 1000;
    const segments = (out.segments || [])
      .map((s) => ({ start: round(s.start), end: round(s.end), text: String(s.text || "").trim() }))
      .filter((s) => s.text);
    const result = { segments, text: String(out.text || segments.map((s) => s.text).join(" ")).trim() };
    if (out.transcription_info?.language) result.language = out.transcription_info.language;
    if (out.transcription_info?.duration) result.duration = round(out.transcription_info.duration);
    return result;
  },
};

// Our own upload links are read straight from storage: a Worker cannot fetch its own hostname.
async function loadAudio(url, env) {
  let own;
  try {
    own = new URL(url);
  } catch {
    throw new ToolError("url is not a valid URL.");
  }
  const m = own.pathname.match(/^\/f\/(f_[A-Za-z0-9_-]+)(\/|$)/);
  if (m && (own.origin === env.ORIGIN || own.hostname.endsWith(".workers.dev"))) {
    const obj = await env.FILES.get(m[1]);
    if (!obj) throw new ToolError("No uploaded file at that link.");
    if (obj.size > MAX_AUDIO) throw new ToolError(`The file is ${obj.size} bytes; the limit is ${MAX_AUDIO}.`);
    return new Uint8Array(await obj.arrayBuffer());
  }
  const u = publicUrl(url);
  if (!u) throw new ToolError("url must be a public http(s) URL.");
  try {
    const { bytes } = await limitedFetch(u.toString(), { maxBytes: MAX_AUDIO, timeoutMs: 30000, maxRedirects: 5 });
    return bytes;
  } catch (e) {
    throw new ToolError(`Could not download the audio: ${e.message}.`);
  }
}
