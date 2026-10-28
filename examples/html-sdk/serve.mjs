/**
 * Static server for the browser-only example. Serves public/ and the SDK
 * from ../../sdk with a strict Content-Security-Policy.
 *
 *   PORT=5173 node serve.mjs
 *
 * For testing against the local mock, set ISSUER (and optionally
 * AUTHORIZATION_ENDPOINT and CLIENT_ID): config.js is then generated from the
 * environment instead of public/config.js.
 */
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(HERE, "public");
const SDK = path.resolve(HERE, "../../sdk/nobleid-auth.js");
const PORT = Number(process.env.PORT || 5173);
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };

const issuerOrigin = process.env.ISSUER ? new URL(process.env.ISSUER).origin : "https://id.nobleid.org";
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src https://www.nobleid.org",
  `connect-src ${issuerOrigin}`,
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

function generatedConfig() {
  const cfg = {
    clientId: process.env.CLIENT_ID || "nbcl_your_client_id",
    issuer: process.env.ISSUER,
    authorizationEndpoint: process.env.AUTHORIZATION_ENDPOINT || undefined,
    scope: process.env.SCOPE || "openid profile works",
  };
  return `window.NOBLEID_CONFIG = Object.assign(${JSON.stringify(cfg)}, { redirectUri: window.location.origin + "/callback.html" });\n`;
}

http
  .createServer((req, res) => {
    const url = new URL(req.url, "http://localhost");
    const headers = { "Content-Security-Policy": CSP, "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store" };
    let file;
    if (url.pathname === "/sdk/nobleid-auth.js") file = SDK;
    else if (url.pathname === "/config.js" && process.env.ISSUER) {
      res.writeHead(200, { ...headers, "Content-Type": TYPES[".js"] });
      return res.end(generatedConfig());
    } else {
      const rel = url.pathname === "/" ? "index.html" : url.pathname.slice(1);
      file = path.resolve(PUBLIC, rel);
      if (!file.startsWith(PUBLIC + path.sep)) file = null; // no path traversal
    }
    if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404, { ...headers, "Content-Type": "text/plain" });
      return res.end("Not found");
    }
    res.writeHead(200, { ...headers, "Content-Type": TYPES[path.extname(file)] || "application/octet-stream" });
    fs.createReadStream(file).pipe(res);
  })
  .listen(PORT, "localhost", () => console.log(`html-sdk example on http://localhost:${PORT}`));
