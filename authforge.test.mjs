import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AuthForgeClient,
  deriveHeartbeatSigningKey,
  deriveSigningKey,
  signPayload,
} from "./authforge.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

async function readVectors() {
  const raw = await readFile(path.join(here, "test_vectors.json"), "utf8");
  return JSON.parse(raw);
}

test("deriveSigningKey and signPayload match validate vectors", async () => {
  const vectors = await readVectors();
  const v = vectors.validate;
  const derivedKey = deriveSigningKey(v.inputs.appSecret, v.inputs.nonce);
  assert.equal(derivedKey.toString("hex"), v.outputs.derivedKeyHex);

  const signature = signPayload(v.inputs.payload, derivedKey);
  assert.equal(signature, v.outputs.signatureHex);
});

test("deriveHeartbeatSigningKey and signPayload match heartbeat vectors", async () => {
  const vectors = await readVectors();
  const h = vectors.heartbeat;
  const derivedKey = deriveHeartbeatSigningKey(h.inputs.sigKey, h.inputs.nonce);
  assert.equal(derivedKey.toString("hex"), h.outputs.derivedKeyHex);

  const signature = signPayload(h.inputs.payload, derivedKey);
  assert.equal(signature, h.outputs.signatureHex);
});

test("heartbeat and validate keys differ for the same nonce", async () => {
  const vectors = await readVectors();
  assert.notEqual(
    vectors.validate.outputs.derivedKeyHex,
    vectors.heartbeat.outputs.derivedKeyHex,
  );
});

test("_deriveHeartbeatKey throws when sigKey not set", () => {
  const client = new AuthForgeClient("app-id", "app-secret", "LOCAL", 900, undefined, () => {});
  assert.throws(() => client._deriveHeartbeatKey("any-nonce"), { message: "missing_sig_key" });
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

test("client state defaults unauthenticated and logout clears sigKey", async () => {
  const client = new AuthForgeClient("app-id", "app-secret", "LOCAL", 900, undefined, () => {});
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionData(), null);
  assert.equal(client._sigKey, null);

  client._validateAndStore = async () => {
    client._sessionToken = "token";
    client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 60;
    client._rawPayloadB64 = "payload";
    client._signature = "signature";
    client._derivedKey = Buffer.alloc(32, 1);
    client._sigKey = "sigkey-abc";
    client._sessionData = { sessionToken: "token" };
    client._authenticated = true;
  };

  const ok = await client.login("license-key");
  assert.equal(ok, true);
  assert.equal(client.isAuthenticated(), true);
  assert.equal(client._sigKey, "sigkey-abc");

  client.logout();
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionData(), null);
  assert.equal(client.getAppVariables(), null);
  assert.equal(client.getLicenseVariables(), null);
  assert.equal(client._sigKey, null);
});

test("constructor rejects invalid heartbeat mode", () => {
  assert.throws(
    () => {
      new AuthForgeClient("app-id", "app-secret", "INVALID", 900, undefined, () => {});
    },
    { message: "heartbeatMode must be LOCAL or SERVER" },
  );
});

test("applySignedResponse rejects nonce mismatch (validate context)", async () => {
  const vectors = await readVectors();
  const v = vectors.validate;
  const client = new AuthForgeClient("app-id", v.inputs.appSecret, "LOCAL", 900, undefined, () => {});
  const payload = Buffer.from(v.inputs.payload, "base64").toString("utf8");
  const payloadObj = JSON.parse(payload);
  payloadObj.nonce = "different-nonce";
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj), "utf8").toString("base64");

  assert.throws(
    () => {
      client._applySignedResponse(
        { status: "ok", payload: payloadB64, signature: v.outputs.signatureHex },
        v.inputs.nonce,
        "license-key",
        "validate",
      );
    },
    { message: "nonce_mismatch" },
  );
});

test("applySignedResponse on validate extracts sigKey from session token", async () => {
  const vectors = await readVectors();
  const v = vectors.validate;
  const h = vectors.heartbeat;
  const client = new AuthForgeClient("app-id", v.inputs.appSecret, "LOCAL", 900, undefined, () => {});
  client._applySignedResponse(
    { status: "ok", payload: v.inputs.payload, signature: v.outputs.signatureHex },
    v.inputs.nonce,
    "license-key",
    "validate",
  );
  assert.equal(client._sigKey, h.inputs.sigKey);
  assert.equal(client.isAuthenticated(), true);
});

test("local heartbeat rejects expired session", async () => {
  const vectors = await readVectors();
  const v = vectors.validate;
  const client = new AuthForgeClient("app-id", v.inputs.appSecret, "LOCAL", 900, undefined, () => {});
  client._rawPayloadB64 = v.inputs.payload;
  client._signature = v.outputs.signatureHex;
  client._derivedKey = deriveSigningKey(v.inputs.appSecret, v.inputs.nonce);
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) - 1;

  assert.throws(
    () => {
      client._localHeartbeat();
    },
    { message: "session_expired" },
  );
});
