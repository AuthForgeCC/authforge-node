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

test("validateLicense verifies response without heartbeat or session mutation", async () => {
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
  client._generateNonce = () => "nonce-validate-001";
  client._postJson = async (path, body, opts) => {
    assert.equal(path, "/auth/validate");
    assert.equal(opts?.skipFailureHook, true);
    assert.equal(body.nonce, "nonce-validate-001");
    return {
      status: "ok",
      payload: validateCase.payload,
      signature: validateCase.signature,
      keyId: "signing-key-1",
    };
  };

  const result = await client.validateLicense("license-key");
  assert.equal(result.valid, true);
  assert.equal(client._heartbeatStarted, false);
  assert.equal(client._heartbeatTimer, null);
  assert.equal(client.isAuthenticated(), false);
  assert.equal(result.sessionToken, "session.validate.token");
  assert.deepEqual(result.appVariables, { tier: "pro" });
});

test("validateLicense returns structured failure without starting heartbeat", async () => {
  const vectors = await readVectors();
  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    "LOCAL",
    900,
    undefined,
    () => {},
  );
  client._postJson = async () => ({
    status: "invalid_key",
    error: "invalid_key",
  });

  const result = await client.validateLicense("bad-key");
  assert.equal(result.valid, false);
  assert.equal(result.code, "invalid_key");
  assert.equal(client._heartbeatStarted, false);
});
