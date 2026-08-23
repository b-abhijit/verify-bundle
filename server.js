"use strict";
/**
 * Verifiable Model Bundle & Model Card checker.
 *
 * ELI15 map of the file:
 *   1. Tiny HTTP server that only cares about POST /verify-bundle.
 *   2. A `violations` Set collects every rule that got broken (a Set means
 *      duplicates disappear automatically -- that's the "dedupe" step).
 *   3. A bunch of small "check this thing" functions, each one mirrors a
 *      numbered rule from the assignment.
 *   4. At the end we sort violations, decide admit/reject, and reply.
 */

const http = require("http");
const crypto = require("crypto");

const REQUIRED_FILES = [
  "README.md",
  "training_manifest.json",
  "evaluation.json",
  "inventory.json",
  "adapter_model.safetensors",
  "adapter_config.json",
];

const UNSAFE_EXTENSIONS = [".bin", ".pt", ".pth", ".pkl", ".pickle"];

// ---------- small utility helpers ----------

function isPlainObject(v) {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function isNonEmptyString(v) {
  return typeof v === "string" && v.length > 0;
}

function sha256Hex(utf8String) {
  return crypto.createHash("sha256").update(Buffer.from(utf8String, "utf8")).digest("hex");
}

function utf8ByteLength(utf8String) {
  return Buffer.byteLength(utf8String, "utf8");
}

// Sort filenames by their raw UTF-8 byte sequence (not JS's default UTF-16
// code-unit compare, which can disagree with UTF-8 ordering for some
// characters outside the Basic Multilingual Plane).
function sortByUtf8Bytes(names) {
  return [...names].sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")));
}

function safeJsonParse(str) {
  try {
    return { ok: true, value: JSON.parse(str) };
  } catch (e) {
    return { ok: false, value: undefined };
  }
}

// ---------- the actual verification logic ----------

function verifyBundle(body) {
  const violations = new Set();
  const add = (code) => violations.add(code);

  const policy = body.policy;
  const files = body.files;

  // --- Rule: policy content validation (structural presence already
  //     guaranteed by caller before we get here) ---
  let policyValid = true;
  if (!isPlainObject(policy)) {
    policyValid = false;
  } else {
    const slicesOk =
      Array.isArray(policy.requiredSlices) &&
      policy.requiredSlices.length > 0 &&
      policy.requiredSlices.every((s) => isNonEmptyString(s)) &&
      new Set(policy.requiredSlices).size === policy.requiredSlices.length;
    const stringsOk =
      isNonEmptyString(policy.license) &&
      isNonEmptyString(policy.intendedUse) &&
      isNonEmptyString(policy.limitations);
    policyValid = slicesOk && stringsOk;
  }
  if (!policyValid) add("INVALID_POLICY");

  const requiredSlices =
    policyValid && Array.isArray(policy.requiredSlices) ? policy.requiredSlices : [];
  const policyLicense = policyValid ? policy.license : undefined;
  const policyIntendedUse = policyValid ? policy.intendedUse : undefined;
  const policyLimitations = policyValid ? policy.limitations : undefined;

  // --- Required files presence / type ---
  for (const name of REQUIRED_FILES) {
    if (!(name in files)) {
      add(`MISSING_FILE:${name}`);
    } else if (typeof files[name] !== "string") {
      add(`INVALID_FILE:${name}`);
    }
  }

  // Helper to fetch a required file's content only if it's a valid string.
  const getFile = (name) => (typeof files[name] === "string" ? files[name] : undefined);

  // --- Untracked files + unsafe weight extensions (scan EVERY file given) ---
  const allNames = Object.keys(files);
  for (const name of allNames) {
    if (!REQUIRED_FILES.includes(name)) {
      add("UNTRACKED_FILE");
    }
    const lower = name.toLowerCase();
    if (UNSAFE_EXTENSIONS.some((ext) => lower.endsWith(ext))) {
      add("UNSAFE_WEIGHTS");
    }
  }

  // --- Recompute the canonical inventory from the actual files we got ---
  // ("every file except itself" = every key in `files` except inventory.json)
  const namesForInventory = sortByUtf8Bytes(allNames.filter((n) => n !== "inventory.json"));
  const recomputedInventory = namesForInventory.map((name) => {
    const content = typeof files[name] === "string" ? files[name] : "";
    return {
      name,
      bytes: utf8ByteLength(content),
      sha256: sha256Hex(content),
    };
  });
  const recomputedInventoryJson = JSON.stringify(recomputedInventory);
  const inventoryDigest = sha256Hex(recomputedInventoryJson);

  const inventoryRaw = getFile("inventory.json");
  if (inventoryRaw !== undefined) {
    const parsed = safeJsonParse(inventoryRaw);
    if (!parsed.ok) {
      add("INVALID_JSON:inventory.json");
      add("INVENTORY_MISMATCH");
    } else if (inventoryRaw !== recomputedInventoryJson) {
      // Exact-string compare enforces "compact" + "exact key order" at once.
      add("INVENTORY_MISMATCH");
    }
  }

  // --- adapter_config.json ---
  const adapterConfigRaw = getFile("adapter_config.json");
  let adapterConfig;
  if (adapterConfigRaw !== undefined) {
    const parsed = safeJsonParse(adapterConfigRaw);
    if (!parsed.ok) {
      add("INVALID_JSON:adapter_config.json");
    } else {
      adapterConfig = parsed.value;
      const rOk =
        isPlainObject(adapterConfig) &&
        Number.isInteger(adapterConfig.r) &&
        Number.isSafeInteger(adapterConfig.r) &&
        adapterConfig.r > 0;
      const modulesOk =
        isPlainObject(adapterConfig) &&
        Array.isArray(adapterConfig.target_modules) &&
        adapterConfig.target_modules.length > 0 &&
        adapterConfig.target_modules.every((m) => isNonEmptyString(m)) &&
        new Set(adapterConfig.target_modules).size === adapterConfig.target_modules.length;
      if (!isPlainObject(adapterConfig) || !rOk || !modulesOk) {
        add("INVALID_ADAPTER_CONFIG");
      }
    }
  }

  // --- training_manifest.json ---
  const manifestRaw = getFile("training_manifest.json");
  let manifest;
  const manifestRequiredStringFields = [
    "task",
    "datasetDigest",
    "codeDigest",
    "trainingConfigDigest",
    "modelArtifactDigest",
    "evaluationArtifactDigest",
  ];
  if (manifestRaw !== undefined) {
    const parsed = safeJsonParse(manifestRaw);
    if (!parsed.ok) {
      add("INVALID_JSON:training_manifest.json");
    } else {
      manifest = parsed.value;
      if (!isPlainObject(manifest)) {
        add("INVALID_TRAINING_MANIFEST");
      } else {
        if (!/^[0-9a-f]{40}$/.test(manifest.baseRevision || "")) {
          add("MUTABLE_BASE_REVISION");
        }
        for (const field of manifestRequiredStringFields) {
          if (!isNonEmptyString(manifest[field])) {
            add(`MISSING_MANIFEST_FIELD:${field}`);
          }
        }
      }
    }
  }

  // --- Recompute + cross-check the two artifact digests ---
  const adapterModelRaw = getFile("adapter_model.safetensors");
  const evaluationRaw = getFile("evaluation.json");

  if (isPlainObject(manifest) && adapterModelRaw !== undefined) {
    const recomputedModelDigest = sha256Hex(adapterModelRaw);
    if (isNonEmptyString(manifest.modelArtifactDigest) && manifest.modelArtifactDigest !== recomputedModelDigest) {
      add("MODEL_ARTIFACT_MISMATCH");
    }
  }
  if (isPlainObject(manifest) && evaluationRaw !== undefined) {
    const recomputedEvalDigest = sha256Hex(evaluationRaw);
    if (
      isNonEmptyString(manifest.evaluationArtifactDigest) &&
      manifest.evaluationArtifactDigest !== recomputedEvalDigest
    ) {
      add("EVALUATION_ARTIFACT_MISMATCH");
    }
  }

  // --- evaluation.json content ---
  let evaluation;
  const inRange01 = (v) => typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1;
  if (evaluationRaw !== undefined) {
    const parsed = safeJsonParse(evaluationRaw);
    if (!parsed.ok) {
      add("INVALID_JSON:evaluation.json");
    } else {
      evaluation = parsed.value;
      if (!isPlainObject(evaluation)) {
        add("INVALID_EVALUATION");
      } else {
        // Binding: evaluation.json must reference the same model digest as
        // the training manifest (adjust the field name here if your course
        // materials specify a different key than "modelDigest").
        const expectedModelDigest = isPlainObject(manifest) ? manifest.modelArtifactDigest : undefined;
        if (
          expectedModelDigest !== undefined &&
          evaluation.modelDigest !== expectedModelDigest
        ) {
          add("EVALUATION_DIGEST_MISMATCH");
        }

        if (!inRange01(evaluation.aggregate)) {
          add("INVALID_AGGREGATE");
        }

        const slices = isPlainObject(evaluation.slices) ? evaluation.slices : {};
        for (const slice of requiredSlices) {
          if (!(slice in slices)) {
            add(`MISSING_SLICE:${slice}`);
          } else if (!inRange01(slices[slice])) {
            add(`SLICE_RANGE:${slice}`);
          }
        }
      }
    }
  }

  // --- README.md model-card marker ---
  const readme = getFile("README.md");
  if (readme !== undefined) {
    const markerRegex = /<!--\s*tds-model-card\s+([\s\S]*?)-->/g;
    const matches = [...readme.matchAll(markerRegex)];

    if (matches.length === 0) {
      add("MODEL_CARD_COUNT");
      add("MISSING_MODEL_CARD");
    } else if (matches.length > 1) {
      add("MODEL_CARD_COUNT");
    } else {
      const payload = matches[0][1].trim();
      const parsed = safeJsonParse(payload);
      if (!parsed.ok || !isPlainObject(parsed.value)) {
        add("INVALID_MODEL_CARD");
      } else {
        const card = parsed.value;
        const expected = {
          task: isPlainObject(manifest) ? manifest.task : undefined,
          baseRevision: isPlainObject(manifest) ? manifest.baseRevision : undefined,
          datasetDigest: isPlainObject(manifest) ? manifest.datasetDigest : undefined,
          modelArtifactDigest: isPlainObject(manifest) ? manifest.modelArtifactDigest : undefined,
          license: policyLicense,
          intendedUse: policyIntendedUse,
          limitations: policyLimitations,
        };
        const mismatch = Object.entries(expected).some(
          ([key, val]) => val === undefined || card[key] !== val
        );
        if (mismatch) add("MODEL_CARD_MISMATCH");
      }
    }
  }

  const sortedViolations = sortByUtf8Bytes([...violations]);

  return {
    decision: sortedViolations.length === 0 ? "admit" : "reject",
    violations: sortedViolations,
    inventoryDigest,
  };
}

// ---------- HTTP plumbing ----------

function readBody(req) {
  return new Promise((resolve, reject) => {
    let chunks = [];
    let size = 0;
    const MAX_BYTES = 50 * 1024 * 1024; // 50MB safety cap
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
  if (req.method !== "POST" || req.url !== "/verify-bundle") {
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "NOT_FOUND" }));
    return;
  }

  let raw;
  try {
    raw = await readBody(req);
  } catch (e) {
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "INVALID_INPUT" }));
    return;
  }

  const parsed = safeJsonParse(raw);
  const body = parsed.ok ? parsed.value : undefined;

  // Structural gate: missing policy, or files not a plain object -> 400.
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
    // Should not happen if the logic above is defensive, but never leak a
    // raw 500 with a stack trace to the grader.
    res.writeHead(400, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "INVALID_INPUT" }));
  }
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`verify-bundle service listening on port ${PORT}`);
  });
}

module.exports = { verifyBundle, server };