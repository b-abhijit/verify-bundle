"use strict";
/**
 * Vercel serverless function.
 *
 * File location matters here: because this file lives at
 *   /api/verify-bundle.js
 * Vercel automatically routes POST/GET/etc requests to
 *   https://<your-app>.vercel.app/verify-bundle
 * to this exact function. There is no server to "start" or "listen" --
 * Vercel spins this function up per-request.
 */

const { verifyBundle, isPlainObject, safeJsonParse } = require("../lib/verify.js");

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

async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(404).json({ error: "NOT_FOUND" });
    return;
  }

  let raw;
  try {
    raw = await readRawBody(req);
  } catch (e) {
    res.status(400).json({ error: "INVALID_INPUT" });
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
    res.status(400).json({ error: "INVALID_INPUT" });
    return;
  }

  try {
    const result = verifyBundle(body);
    res.status(200).json(result);
  } catch (e) {
    res.status(400).json({ error: "INVALID_INPUT" });
  }
}

module.exports = handler;

// We turn OFF Vercel's automatic body parsing and read the raw bytes
// ourselves. Why: automatic parsing throws its own generic error on bad
// JSON, and we specifically need to return {"error":"INVALID_INPUT"} with
// a 400 status ourselves, matching the assignment's exact contract.
module.exports.config = {
  api: {
    bodyParser: false,
  },
};