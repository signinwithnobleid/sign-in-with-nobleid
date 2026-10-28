/**
 * Minimal browser-like HTTP helpers for the end-to-end tests: a cookie jar
 * keyed by host, manual redirects, and a few HTML helpers. No dependencies.
 */

export class CookieJar {
  constructor() {
    this.byHost = new Map(); // host -> Map(name -> value)
  }
  store(url, res) {
    const host = new URL(url).host;
    const list = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    if (!list.length) return;
    let jar = this.byHost.get(host);
    if (!jar) this.byHost.set(host, (jar = new Map()));
    for (const line of list) {
      const [pair, ...attrs] = line.split(";");
      const eq = pair.indexOf("=");
      if (eq < 0) continue;
      const name = pair.slice(0, eq).trim();
      const value = pair.slice(eq + 1).trim();
      const a = attrs.map((s) => s.trim().toLowerCase());
      const maxAge = a.find((s) => s.startsWith("max-age="));
      const expires = a.find((s) => s.startsWith("expires="));
      const expired =
        (maxAge && Number(maxAge.slice(8)) <= 0) ||
        (expires && Date.parse(expires.slice(8)) < Date.now()) ||
        value === "";
      if (expired) jar.delete(name);
      else jar.set(name, value);
    }
  }
  header(url) {
    const jar = this.byHost.get(new URL(url).host);
    if (!jar || !jar.size) return undefined;
    return [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
  }
}

/** One request, no automatic redirects, cookies from/to the jar. */
export async function request(jar, url, { method = "GET", headers = {}, body, origin } = {}) {
  const h = { "User-Agent": "nobleid-kit-e2e", Accept: "text/html,application/json;q=0.9,*/*;q=0.8", ...headers };
  const cookie = jar && jar.header(url);
  if (cookie) h.Cookie = cookie;
  if (origin) h.Origin = origin;
  let payload = body;
  if (body && typeof body === "object" && !(body instanceof URLSearchParams) && typeof body !== "string") {
    payload = new URLSearchParams(body).toString();
    h["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (body instanceof URLSearchParams) {
    payload = body.toString();
    h["Content-Type"] = "application/x-www-form-urlencoded";
  }
  const res = await fetch(url, { method, headers: h, body: payload, redirect: "manual" });
  if (jar) jar.store(url, res);
  const text = await res.text();
  const location = res.headers.get("location");
  return { status: res.status, headers: res.headers, text, location: location ? new URL(location, url).toString() : null, url };
}

/** Follow redirects while `keepGoing(nextUrl)` is true. Returns the last response. */
export async function follow(jar, first, keepGoing, max = 15) {
  let res = first;
  for (let i = 0; i < max && res.location && res.status >= 300 && res.status < 400 && keepGoing(res.location); i++) {
    res = await request(jar, res.location);
  }
  return res;
}

const ENTITIES = { "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&#39;": "'", "&#x27;": "'", "&#34;": '"', "&#x22;": '"', "&#47;": "/", "&#x2F;": "/", "&#x2f;": "/" };

export function unescapeHtml(s) {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCodePoint(Number(d)))
    .replace(/&(amp|lt|gt|quot|apos);/g, (m) => (m === "&apos;" ? "'" : ENTITIES[m]));
}

/** Parse the JSON inside <pre id="..."> (HTML-escaped). */
export function preJson(html, id) {
  const m = html.match(new RegExp(`<pre[^>]*\\bid=["']${id}["'][^>]*>([\\s\\S]*?)</pre>`, "i"));
  if (!m) return null;
  return JSON.parse(unescapeHtml(m[1]));
}

function attrs(tag) {
  const out = {};
  for (const m of tag.matchAll(/([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g)) {
    out[m[1].toLowerCase()] = unescapeHtml(m[3] ?? m[4] ?? m[5] ?? "");
  }
  return out;
}

/** Hidden inputs of the first <form> whose action ends with `actionPath`. */
export function formFields(html, actionPath) {
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const a = attrs(m[1]);
    if (!a.action) continue;
    let p;
    try {
      p = new URL(a.action, "http://x").pathname;
    } catch {
      continue;
    }
    if (p !== actionPath) continue;
    const fields = {};
    for (const i of m[2].matchAll(/<input\b([^>]*)>/gi)) {
      const ia = attrs(i[1]);
      if (ia.name && (ia.type || "text").toLowerCase() === "hidden") fields[ia.name] = ia.value ?? "";
    }
    return fields;
  }
  return null;
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
