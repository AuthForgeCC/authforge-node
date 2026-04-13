import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { AuthForgeClient, deriveSigningKey, signPayload } from "./authforge.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

async function readVectors() {
  const raw = await readFile(path.join(here, "test_vectors.json"), "utf8");
  return JSON.parse(raw);
}

test("deriveSigningKey and signPayload match test vectors", async () => {
  const vectors = await readVectors();
  const derivedKey = deriveSigningKey(vectors.inputs.appSecret, vectors.inputs.nonce);
  assert.equal(derivedKey.toString("hex"), vectors.outputs.derivedKeyHex);

  const signature = signPayload(vectors.inputs.payload, derivedKey);
  assert.equal(signature, vectors.outputs.signatureHex);
});

test("HWID format is 64-char hex", () => {
  const client = new AuthForgeClient("app-id", "app-secret", "SERVER", 900, undefined, () => {});
  assert.match(client._hwid, /^[a-f0-9]{64}$/);
});

test("nonce generation is unique and hex encoded", () => {
  const client = new AuthForgeClient("app-id", "app-secret", "SERVER", 900, undefined, () => {});
  const nonceA = client._generateNonce();
  const nonceB = client._generateNonce();

  assert.match(nonceA, /^[a-f0-9]{32}$/);
  assert.match(nonceB, /^[a-f0-9]{32}$/);
  assert.notEqual(nonceA, nonceB);
});

test("client state defaults unauthenticated and logout clears state", async () => {
  const client = new AuthForgeClient("app-id", "app-secret", "LOCAL", 900, undefined, () => {});
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionData(), null);

  client._validateAndStore = async () => {
    client._sessionToken = "token";
    client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 60;
    client._rawPayloadB64 = "payload";
    client._signature = "signature";
    client._derivedKey = Buffer.alloc(32, 1);
    client._sessionData = { sessionToken: "token" };
    client._authenticated = true;
  };

  const ok = await client.login("license-key");
  assert.equal(ok, true);
  assert.equal(client.isAuthenticated(), true);

  client.logout();
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionData(), null);
  assert.equal(client.getAppVariables(), null);
  assert.equal(client.getLicenseVariables(), null);
});

test("constructor rejects invalid heartbeat mode", () => {
  assert.throws(
    () => {
      new AuthForgeClient("app-id", "app-secret", "INVALID", 900, undefined, () => {});
    },
    { message: "heartbeatMode must be LOCAL or SERVER" },
  );
});

test("applySignedResponse rejects nonce mismatch", async () => {
  const vectors = await readVectors();
  const client = new AuthForgeClient("app-id", vectors.inputs.appSecret, "LOCAL", 900, undefined, () => {});
  const payload = Buffer.from(vectors.inputs.payload, "base64").toString("utf8");
  const payloadObj = JSON.parse(payload);
  payloadObj.nonce = "different-nonce";
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64");

  assert.throws(
    () => {
      client._applySignedResponse(
        { status: "ok", payload: payloadB64, signature: vectors.outputs.signatureHex },
        vectors.inputs.nonce,
        "license-key",
      );
    },
    { message: "nonce_mismatch" },
  );
});

test("local heartbeat rejects expired session", async () => {
  const vectors = await readVectors();
  const client = new AuthForgeClient("app-id", vectors.inputs.appSecret, "LOCAL", 900, undefined, () => {});
  client._rawPayloadB64 = vectors.inputs.payload;
  client._signature = vectors.outputs.signatureHex;
  client._derivedKey = deriveSigningKey(vectors.inputs.appSecret, vectors.inputs.nonce);
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) - 1;

  assert.throws(
    () => {
      client._localHeartbeat();
    },
    { message: "session_expired" },
  );
});
