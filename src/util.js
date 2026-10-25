// Small helpers shared by the OAuth server, the MCP endpoint and the tools.

export const enc = new TextEncoder();

export function randomToken(bytes = 32) {
  const b = crypto.getRandomValues(new Uint8Array(bytes));
  return base64url(b);
}

export function base64url(bytes) {
  let s = "";
  for (const x of bytes) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
}

export async function sha256hex(text) {
  return [...(await sha256(text))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Constant-time string compare: hash both sides, then compare the digests.
export async function safeEqual(a, b) {
  const [ha, hb] = await Promise.all([sha256(String(a)), sha256(String(b))]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}

export function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...headers },
  });
}

export function html(body, status = 200, headers = {}) {
  return new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "x-frame-options": "DENY",
      "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
      "referrer-policy": "no-referrer",
      ...headers,
    },
  });
}

export function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
}

export const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

// Public http(s) URL check used before the server fetches anything a caller names
// (client metadata documents, audio URLs). Blocks loopback, private and link-local hosts.
export function publicUrl(raw, { httpsOnly = false } = {}) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && (httpsOnly || u.protocol !== "http:")) return null;
  if (u.username || u.password) return null;
  const h = u.hostname.toLowerCase();
  if (LOOPBACK_HOSTS.has(h) || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return null;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(h)) {
    const [a, b] = h.split(".").map(Number);
    if (a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224) return null;
  }
  if (h.startsWith("[")) {
    const v6 = h.slice(1, -1);
    if (v6 === "::1" || v6 === "::" || /^f[cd]/.test(v6) || /^fe[89ab]/.test(v6) || v6.startsWith("::ffff:")) return null;
  }
  return u;
}

// Fetch with a byte limit and a timeout. Returns { bytes, contentType } or throws.
// Each redirect hop is checked with publicUrl again.
export async function limitedFetch(url, { maxBytes, timeoutMs = 20000, accept, maxRedirects = 0 } = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort("timeout"), timeoutMs);
  try {
    let res;
    let current = url;
    for (let hop = 0; ; hop++) {
      res = await fetch(current, { redirect: "manual", signal: ctl.signal, headers: accept ? { accept } : {} });
      if (res.status < 300 || res.status >= 400) break;
      const next = res.headers.get("location");
      if (hop >= maxRedirects || !next) throw new Error(`the URL redirects (HTTP ${res.status}); give the final URL`);
      const checked = publicUrl(new URL(next, current).toString());
      if (!checked) throw new Error("the URL redirects to an address this server does not fetch");
      current = checked.toString();
    }
    if (!res.ok) throw new Error(`fetching the URL gave HTTP ${res.status}`);
    const len = Number(res.headers.get("content-length") || 0);
    if (len && len > maxBytes) throw new Error(`the file is ${len} bytes; the limit is ${maxBytes}`);
    const reader = res.body.getReader();
    const chunks = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        ctl.abort("too large");
        throw new Error(`the file is larger than the limit of ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      bytes.set(c, off);
      off += c.byteLength;
    }
    return { bytes, contentType: res.headers.get("content-type") || "" };
  } finally {
    clearTimeout(timer);
  }
}

export function bytesToBase64(bytes) {
  let s = "";
  const step = 0x8000;
  for (let i = 0; i < bytes.length; i += step) s += String.fromCharCode.apply(null, bytes.subarray(i, i + step));
  return btoa(s);
}

export function base64ToBytes(b64) {
  const clean = String(b64).replace(/^data:[^,]*;base64,/, "").replace(/[\s]/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(clean);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function nowIso() {
  return new Date().toISOString();
}
