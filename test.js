const crypto = require("crypto");
const { verifyBundle } = require("./server.js");

function sha256Hex(s) {
  return crypto.createHash("sha256").update(Buffer.from(s, "utf8")).digest("hex");
}

// --- Build a fully valid bundle from scratch ---
const adapterModel = "FAKE_SAFETENSORS_BYTES_FOR_TESTING";
const modelDigest = sha256Hex(adapterModel);

const evaluationObj = {
  modelDigest,
  aggregate: 0.87,
  slices: { critical: 0.91, other: 0.5 },
};
const evaluationJson = JSON.stringify(evaluationObj);
const evalDigest = sha256Hex(evaluationJson);

const manifestObj = {
  baseRevision: "a".repeat(40),
  task: "text-classification",
  datasetDigest: "d".repeat(10),
  codeDigest: "c".repeat(10),
  trainingConfigDigest: "t".repeat(10),
  modelArtifactDigest: modelDigest,
  evaluationArtifactDigest: evalDigest,
};
const manifestJson = JSON.stringify(manifestObj);

const adapterConfigObj = { r: 8, target_modules: ["q_proj", "v_proj"] };
const adapterConfigJson = JSON.stringify(adapterConfigObj);

const cardObj = {
  task: manifestObj.task,
  baseRevision: manifestObj.baseRevision,
  datasetDigest: manifestObj.datasetDigest,
  modelArtifactDigest: manifestObj.modelArtifactDigest,
  license: "MIT",
  intendedUse: "Research demo",
  limitations: "Not for production",
};
const readme = `# My Model\n\nSome prose.\n\n<!-- tds-model-card ${JSON.stringify(cardObj)} -->\n\nMore prose.\n`;

const filesWithoutInventory = {
  "README.md": readme,
  "training_manifest.json": manifestJson,
  "evaluation.json": evaluationJson,
  "adapter_model.safetensors": adapterModel,
  "adapter_config.json": adapterConfigJson,
};

function byteLen(s) {
  return Buffer.byteLength(s, "utf8");
}
const inventoryArr = Object.keys(filesWithoutInventory)
  .sort((a, b) => Buffer.compare(Buffer.from(a, "utf8"), Buffer.from(b, "utf8")))
  .map((name) => ({
    name,
    bytes: byteLen(filesWithoutInventory[name]),
    sha256: sha256Hex(filesWithoutInventory[name]),
  }));
const inventoryJson = JSON.stringify(inventoryArr);

const files = { ...filesWithoutInventory, "inventory.json": inventoryJson };

const policy = {
  requiredSlices: ["critical"],
  license: "MIT",
  intendedUse: "Research demo",
  limitations: "Not for production",
};

console.log("--- Valid bundle ---");
console.log(JSON.stringify(verifyBundle({ policy, files }), null, 2));

console.log("\n--- Tampered bundle (flipped one byte in adapter_model) ---");
const badFiles = { ...files, "adapter_model.safetensors": adapterModel + "X" };
console.log(JSON.stringify(verifyBundle({ policy, files: badFiles }), null, 2));

console.log("\n--- Missing README marker ---");
const noMarkerFiles = { ...files, "README.md": "# no marker here\n" };
console.log(JSON.stringify(verifyBundle({ policy, files: noMarkerFiles }), null, 2));