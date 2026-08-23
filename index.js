"use strict";
/**
 * Fallback entrypoint for Vercel's "Node.js Server" framework preset.
 * This preset wants ONE root file exporting either a request-handler
 * function or an http.Server instance -- it does not look inside /api.
 *
 * We export the raw http.Server (no .listen() call -- Vercel binds the
 * port itself when it imports this module).
 */

const http = require("http");
const { verifyBundle, isPlainObject, safeJsonParse } = require("./lib/verify.js");

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    const MAX_BYTES = 50 * 1024 * 1024;
    req.on("data", (chunk) => {
      size += chunk.length;
      if (size > MAX_BYTES) {
        reject(new Error("payload too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const path = (req.url || "").split("?")[0];
  const isVerifyRoute = path === "/verify-bundle" || path === "/api/verify-bundle";

  if (req.method !== "POST" || !isVerifyRoute) {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "NOT_FOUND" }));
    return;
  }

  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "INVALID_INPUT" }));
    return;
  }

  const parsed = safeJsonParse(raw);
  const body = parsed.ok ? parsed.value : undefined;

  if (
    !isPlainObject(body) ||
    body.policy === undefined ||
    body.policy === null ||
    !isPlainObject(body.files)
  ) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "INVALID_INPUT" }));
    return;
  }

  try {
    const result = verifyBundle(body);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result));
  } catch (e) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "INVALID_INPUT" }));
  }
});

// If run directly (e.g. `node index.js` locally), actually listen.
// If imported by Vercel's runtime, it will bind the port itself.
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`listening on ${PORT}`));
}

module.exports = server;