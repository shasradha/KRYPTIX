const http = require("http");
const fs = require("fs");
const path = require("path");

const MIME_TYPES = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "application/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".webp": "image/webp",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".mp4": "video/mp4",
  ".webm": "video/webm",
  ".mp3": "audio/mpeg",
  ".ogg": "audio/ogg",
  ".wav": "audio/wav"
};

const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "base-uri 'self'",
  "frame-ancestors 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "script-src 'self' https://unpkg.com",
  "style-src 'self' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com data:",
  "img-src 'self' blob: data:",
  "media-src 'self' blob: data:",
  "connect-src 'self' http: https: ws: wss: stun: turn:",
  "worker-src 'self' blob:"
].join("; ");

const BASE_HEADERS = {
  "Content-Security-Policy": CONTENT_SECURITY_POLICY,
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Resource-Policy": "same-origin",
  "Permissions-Policy": "camera=(self), microphone=(self), geolocation=(), browsing-topics=(), interest-cohort=(), serial=(), usb=(), bluetooth=()",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-Permitted-Cross-Domain-Policies": "none"
};

function cacheControlFor(extension) {
  return extension === ".html" ? "no-store" : "public, max-age=3600, stale-while-revalidate=86400";
}

function sendJson(response, statusCode, payload) {
  response.writeHead(statusCode, {
    ...BASE_HEADERS,
    "Cache-Control": "no-store",
    "Content-Type": "application/json; charset=utf-8"
  });
  response.end(JSON.stringify(payload));
}

function sendText(response, statusCode, message) {
  response.writeHead(statusCode, {
    ...BASE_HEADERS,
    "Cache-Control": "no-store",
    "Content-Type": "text/plain; charset=utf-8"
  });
  response.end(message);
}

function createServer(rootDir = path.join(__dirname, "www")) {
  const normalizedRoot = path.resolve(rootDir);

  return http.createServer((request, response) => {
    const requestPath = decodeURIComponent((request.url || "/").split("?")[0]);

    if (requestPath === "/health") {
      sendJson(response, 200, {
        app: "Kryptix",
        status: "ok",
        time: new Date().toISOString()
      });
      return;
    }

    const relativePath = requestPath === "/" ? "index.html" : requestPath.replace(/^\/+/, "");
    const filePath = path.resolve(normalizedRoot, relativePath);
    const relativeToRoot = path.relative(normalizedRoot, filePath);

    if (relativeToRoot.startsWith("..") || path.isAbsolute(relativeToRoot)) {
      sendText(response, 403, "Forbidden");
      return;
    }

    fs.readFile(filePath, (error, data) => {
      if (error) {
        sendText(response, error.code === "ENOENT" ? 404 : 500, error.code === "ENOENT" ? "Not found" : "Server error");
        return;
      }

      const extension = path.extname(filePath).toLowerCase();
      response.writeHead(200, {
        ...BASE_HEADERS,
        "Cache-Control": cacheControlFor(extension),
        "Content-Type": MIME_TYPES[extension] || "application/octet-stream"
      });
      response.end(data);
    });
  });
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 8787;
  const server = createServer();
  server.listen(port, () => {
    console.log(`Kryptix local server is running at http://localhost:${port}`);
  });
}

module.exports = { createServer };
