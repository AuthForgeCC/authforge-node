import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AuthForgeClient,
  parseLicenseFile,
  verifyLicenseFile,
  verifyPayloadSignatureEd25519,
} from "./authforge.mjs";

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
    new AuthForgeClient("app-id", "app-secret");
  });
});

test("default policy is grace period: onlineHeartbeat false, heartbeatMode LOCAL", () => {
  const client = new AuthForgeClient({
    appId: "app-id",
    appSecret: "app-secret",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    onFailure: () => {},
  });
  assert.equal(client.onlineHeartbeat, false);
  assert.equal(client.heartbeatMode, "LOCAL");
});

test("legacy heartbeatMode SERVER maps to onlineHeartbeat true", () => {
  const client = new AuthForgeClient({
    appId: "app-id",
    appSecret: "app-secret",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    heartbeatMode: "SERVER",
    onFailure: () => {},
  });
  assert.equal(client.onlineHeartbeat, true);
  assert.equal(client.heartbeatMode, "SERVER");
});

test("legacy heartbeatMode LOCAL maps to onlineHeartbeat false", () => {
  const client = new AuthForgeClient({
    appId: "app-id",
    appSecret: "app-secret",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    heartbeatMode: "LOCAL",
    onFailure: () => {},
  });
  assert.equal(client.onlineHeartbeat, false);
  assert.equal(client.heartbeatMode, "LOCAL");
});

test("onlineHeartbeat: true enables online check-ins without heartbeatMode", () => {
  const client = new AuthForgeClient({
    appId: "app-id",
    appSecret: "app-secret",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    onlineHeartbeat: true,
    onFailure: () => {},
  });
  assert.equal(client.onlineHeartbeat, true);
  assert.equal(client.heartbeatMode, "SERVER");
});

test("invalid heartbeatMode still throws", () => {
  assert.throws(
    () => {
      new AuthForgeClient({
        appId: "app-id",
        appSecret: "app-secret",
        publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        heartbeatMode: "SOMETIMES",
        onFailure: () => {},
      });
    },
    { message: "heartbeatMode must be LOCAL or SERVER" },
  );
});

test("legacy positional heartbeatMode still works and emits a deprecation warning", async () => {
  const warnings = [];
  const onWarning = (warning) => warnings.push(warning);
  process.on("warning", onWarning);
  try {
    const client = new AuthForgeClient(
      "app-id",
      "app-secret",
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "server",
      900,
      undefined,
      () => {},
    );
    assert.equal(client.onlineHeartbeat, true);
    assert.equal(client.heartbeatMode, "SERVER");
    // Warnings are delivered asynchronously on the next tick.
    await new Promise((resolve) => setImmediate(resolve));
    const deprecation = warnings.find((warning) => warning.name === "DeprecationWarning");
    assert.ok(deprecation);
    assert.match(deprecation.message, /onlineHeartbeat: true/);
  } finally {
    process.off("warning", onWarning);
  }
});

test("grace period check verifies stored signature with public key", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  assert.ok(validateCase);

  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    undefined,
    900,
    undefined,
    () => {},
  );
  client._rawPayloadB64 = validateCase.payload;
  client._signature = validateCase.signature;
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 60;
  client._gracePeriodCheck();
});

test("grace period check fails after the session TTL expires", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  assert.ok(validateCase);

  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    undefined,
    900,
    undefined,
    () => {},
  );
  client._rawPayloadB64 = validateCase.payload;
  client._signature = validateCase.signature;
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) - 1;
  assert.throws(() => client._gracePeriodCheck(), { message: "session_expired" });
});

test("validateLicense verifies response without heartbeat or session mutation", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  assert.ok(validateCase);

  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    undefined,
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

test("verifyPayloadSignatureEd25519 accepts an array of trusted keys", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  assert.ok(validateCase);
  // Bogus key first, real key second — verification must succeed by trying
  // each entry instead of bailing on the first miss.
  const decoyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const valid = verifyPayloadSignatureEd25519(
    validateCase.payload,
    validateCase.signature,
    [decoyKey, vectors.publicKey],
  );
  assert.equal(valid, true);
});

test("verifyPayloadSignatureEd25519 also accepts comma-separated env-var form", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  const decoyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const combined = `${decoyKey},${vectors.publicKey}`;
  const valid = verifyPayloadSignatureEd25519(
    validateCase.payload,
    validateCase.signature,
    combined,
  );
  assert.equal(valid, true);
});

test("client constructor accepts an array of public keys (rotation set)", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  const decoyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    [decoyKey, vectors.publicKey],
    undefined,
    900,
    undefined,
    () => {},
  );
  assert.deepEqual(client.publicKeys, [decoyKey, vectors.publicKey]);
  assert.equal(client.publicKey, decoyKey);
  // Grace period verification must still succeed because the *second* key
  // in the trust list matches the signature.
  client._rawPayloadB64 = validateCase.payload;
  client._signature = validateCase.signature;
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 60;
  client._gracePeriodCheck();
});

test("validateLicense returns structured failure without starting heartbeat", async () => {
  const vectors = await readVectors();
  const client = new AuthForgeClient(
    "app-id",
    "app-secret",
    vectors.publicKey,
    undefined,
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

// ---------------------------------------------------------------------------
// Offline license files (`.authforge`)
// ---------------------------------------------------------------------------

async function readOfflineVectors() {
  const raw = await readFile(path.join(here, "offline_license_vectors.json"), "utf8");
  return JSON.parse(raw);
}

function goodCase(vectors) {
  return vectors.cases.find((c) => c.name === "good_bound");
}

// Client-level tests run against the wall clock, so they use the lifetime
// vector (expiresAt: null) rather than good_bound, which expires in 2027.
function lifetimeCase(vectors) {
  return vectors.cases.find((c) => c.name === "good_lifetime");
}

test("offline vectors: every case verifies to the expected result", async () => {
  const vectors = await readOfflineVectors();
  assert.ok(vectors.cases.length >= 15);
  for (const c of vectors.cases) {
    const result = verifyLicenseFile({
      file: c.file,
      appId: c.appId,
      publicKey: c.publicKey,
      hwid: c.hwid,
      now: new Date(c.now),
    });
    const got = result.ok ? "ok" : result.error;
    assert.equal(got, c.expect, `${c.name}: expected ${c.expect}, got ${got}`);
    if (result.ok && c.payload) {
      assert.deepEqual(result.license.payload, c.payload);
      assert.equal(result.payloadBase64, c.payloadBase64);
      assert.equal(result.signatureBase64, c.signatureBase64);
    }
  }
});

test("offline vectors: parseLicenseFile recovers the canonical signed string", async () => {
  const vectors = await readOfflineVectors();
  const c = goodCase(vectors);
  const parsed = parseLicenseFile(c.file);
  assert.equal(parsed.payloadBase64, c.payloadBase64);
  assert.equal(parsed.signatureBase64, c.signatureBase64);
  assert.equal(parsed.headers.Version, "1");
  assert.equal(parsed.headers["App-Id"], c.appId);
  assert.equal(parseLicenseFile("nope"), null);
});

test("offline vectors: good file exposes decoded entitlements", async () => {
  const vectors = await readOfflineVectors();
  const c = goodCase(vectors);
  const result = verifyLicenseFile({ file: c.file, appId: c.appId, publicKey: c.publicKey, hwid: c.hwid, now: new Date(c.now) });
  assert.equal(result.ok, true);
  assert.equal(result.license.licenseKey, "TEST-KEY0-0000-0000");
  assert.equal(result.license.keyId, "kid-test-0001");
  assert.deepEqual(result.license.hwidPolicy, { mode: "bound", hwids: ["testhwid", "second-machine"] });
  assert.deepEqual(result.license.licenseVariables, { tier: "pro", seats: 3, beta: true });
  assert.deepEqual(result.license.appVariables, { theme: "dark" });
  assert.equal(result.license.label, "Vector license");
});

test("loginFromFile authenticates offline without any network or heartbeat", async () => {
  const vectors = await readOfflineVectors();
  const c = lifetimeCase(vectors);
  const failures = [];
  const client = new AuthForgeClient({
    appId: c.appId,
    appSecret: "unused-offline",
    publicKey: c.publicKey,
    hwidOverride: c.hwid,
    onFailure: (reason, error) => failures.push([reason, error?.message]),
  });
  client._postJson = async () => {
    throw new Error("network must not be used for offline files");
  };

  assert.equal(client.getHwid(), c.hwid);
  assert.equal(client.getSessionKind(), null);
  assert.equal(client.loginFromFile(c.file), true);
  assert.equal(client.isAuthenticated(), true);
  assert.equal(client.getSessionKind(), "offline");
  // No token sentinel: an offline session has no server session at all.
  assert.equal(client._sessionToken, null);
  assert.equal(client._heartbeatStarted, false);
  assert.equal(client._heartbeatTimer, null);
  assert.deepEqual(client.getLicenseVariables(), { tier: "pro", seats: 3, beta: true });
  assert.deepEqual(client.getAppVariables(), { theme: "dark" });
  assert.equal(client.getSessionData().licenseKey, "TEST-KEY0-0000-0000");
  assert.equal(client.getOfflineLicense().jti, "00000000-0000-4000-8000-000000000003");
  assert.equal(client.getOfflineLicense().expiresAt, null);
  assert.deepEqual(failures, []);

  client.logout();
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionKind(), null);
  assert.equal(client.getOfflineLicense(), null);
});

test("offline session: selfBan is a local offline_session error and never posts", async () => {
  const vectors = await readOfflineVectors();
  const c = lifetimeCase(vectors);
  const posts = [];
  const client = new AuthForgeClient({
    appId: c.appId,
    appSecret: "unused-offline",
    publicKey: c.publicKey,
    hwidOverride: c.hwid,
    // Closed port: any accidental network call fails loudly instead of hanging.
    apiBaseUrl: "http://127.0.0.1:9",
    onFailure: () => {},
  });
  client._postJson = async (p, body) => {
    posts.push([p, body]);
    return { status: "ok" };
  };
  assert.equal(client.loginFromFile(c.file), true);

  await assert.rejects(client.selfBan(), { message: "offline_session" });
  await assert.rejects(client.selfBan({ revokeLicense: false, blacklistHwid: false }), { message: "offline_session" });
  assert.deepEqual(posts, []);
  // Still authenticated offline afterwards; nothing was torn down.
  assert.equal(client.isAuthenticated(), true);

  // An explicit licenseKey is a request about a different credential and
  // legitimately takes the pre-session path with a fresh nonce.
  await client.selfBan({ licenseKey: "OTHER-KEY0-0000-0000" });
  assert.equal(posts.length, 1);
  assert.equal(posts[0][0], "/auth/selfban");
  assert.equal(posts[0][1].licenseKey, "OTHER-KEY0-0000-0000");
  assert.equal(posts[0][1].revokeLicense, false);
  assert.ok(typeof posts[0][1].nonce === "string" && posts[0][1].nonce.length > 0);
  assert.ok(!("sessionToken" in posts[0][1]));
});

test("offline session: heartbeat and grace entry points are no-ops", async () => {
  const vectors = await readOfflineVectors();
  const c = lifetimeCase(vectors);
  const client = new AuthForgeClient({
    appId: c.appId,
    appSecret: "unused-offline",
    publicKey: c.publicKey,
    hwidOverride: c.hwid,
    onlineHeartbeat: true,
    onFailure: (reason) => {
      throw new Error(`unexpected failure ${reason}`);
    },
  });
  client._postJson = async () => {
    throw new Error("network must not be used for offline files");
  };
  assert.equal(client.loginFromFile(c.file), true);

  // Even if something calls the internal entry points, an offline session
  // never starts a timer, never checks in and never runs the grace check.
  client._startHeartbeatOnce();
  assert.equal(client._heartbeatStarted, false);
  assert.equal(client._heartbeatTimer, null);
  await client._heartbeatTick();
  assert.equal(client.isAuthenticated(), true);
  assert.equal(client.getSessionKind(), "offline");
});

test("loginFromFile rejects bad signature, wrong key, expired and HWID mismatch via onFailure", async () => {
  const vectors = await readOfflineVectors();
  const byName = Object.fromEntries(vectors.cases.map((c) => [c.name, c]));
  // Lifetime file: rejection reasons below must not turn into `expired` over time.
  const good = byName.good_lifetime;

  const make = (overrides = {}) => {
    const failures = [];
    const client = new AuthForgeClient({
      appId: good.appId,
      appSecret: "unused-offline",
      publicKey: good.publicKey,
      hwidOverride: good.hwid,
      onFailure: (reason, error) => failures.push([reason, error?.message]),
      ...overrides,
    });
    return { client, failures };
  };

  {
    const { client, failures } = make();
    assert.equal(client.loginFromFile(byName.bad_signature_tampered_body.file), false);
    assert.deepEqual(failures, [["offline_login_failed", "bad_signature"]]);
    assert.equal(client.isAuthenticated(), false);
  }
  {
    const { client, failures } = make({ publicKey: vectors.keys.wrongPublicKey });
    assert.equal(client.loginFromFile(good.file), false);
    assert.deepEqual(failures, [["offline_login_failed", "bad_signature"]]);
  }
  {
    const { client, failures } = make();
    assert.equal(client.loginFromFile(byName.expired.file), false);
    assert.deepEqual(failures, [["offline_login_failed", "expired"]]);
  }
  {
    const { client, failures } = make({ hwidOverride: "otherhwid" });
    assert.equal(client.loginFromFile(good.file), false);
    assert.deepEqual(failures, [["offline_login_failed", "hwid_mismatch"]]);
  }
  {
    const { client, failures } = make({ appId: "other-app" });
    assert.equal(client.loginFromFile(good.file), false);
    assert.deepEqual(failures, [["offline_login_failed", "wrong_app"]]);
  }
  {
    const { client, failures } = make();
    assert.equal(client.loginFromFile("garbage"), false);
    // Not armor and not a readable path -> read error surfaces, never process.exit.
    assert.equal(failures.length, 1);
    assert.equal(failures[0][0], "offline_login_failed");
  }
});

test("loginFromFile reads a file from disk and client.verifyLicenseFile is side-effect free", async () => {
  const vectors = await readOfflineVectors();
  const c = lifetimeCase(vectors);
  const dir = await mkdtemp(path.join(os.tmpdir(), "authforge-offline-"));
  const filePath = path.join(dir, "license.authforge");
  await writeFile(filePath, c.file, "utf8");
  try {
    const client = new AuthForgeClient({
      appId: c.appId,
      appSecret: "unused-offline",
      publicKey: c.publicKey,
      hwidOverride: c.hwid,
      onFailure: () => {},
    });
    const checked = client.verifyLicenseFile(filePath, { now: new Date(c.now) });
    assert.equal(checked.ok, true);
    assert.equal(client.isAuthenticated(), false);
    assert.equal(client.loginFromFile(filePath), true);
    assert.equal(client.isAuthenticated(), true);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
