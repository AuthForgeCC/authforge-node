import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { AuthForgeClient, verifyPayloadSignatureEd25519 } from "./authforge.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

async function readVectors() {
  const raw = await readFile(path.join(here, "test_vectors.json"), "utf8");
  return JSON.parse(raw);
}

test("ed25519 vectors verify expected signatures", async () => {
  const vectors = await readVectors();
  for (const vectorCase of vectors.cases) {
    const valid = verifyPayloadSignatureEd25519(
      vectorCase.payload,
      vectorCase.signature,
      vectors.publicKey,
    );
    assert.equal(valid, vectorCase.shouldVerify);
  }
});

test("client constructor requires public key", () => {
  assert.throws(() => {
    // @ts-expect-error constructor hard break
    new AuthForgeClient("app-id", "app-secret", "LOCAL");
  });
});

test("local heartbeat verifies stored signature with public key", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  assert.ok(validateCase);

  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    "LOCAL",
    900,
    undefined,
    () => {},
  );
  client._rawPayloadB64 = validateCase.payload;
  client._signature = validateCase.signature;
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 60;
  client._localHeartbeat();
});
