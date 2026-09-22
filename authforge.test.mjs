import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  AuthForgeClient,
  AuthForgeError,
  definitiveErrorCodes,
  formatActivationRequest,
  isTransientError,
  parseLicenseFile,
  transientErrorCodes,
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
// Online check-in failures (`/auth/heartbeat`)
// ---------------------------------------------------------------------------

/**
 * Local HTTP server answering each request with `respond(req)` -> [status, body]
 * (or a promise of it). `null` never answers (timeout case).
 */
async function withServer(respond, fn) {
  let requests = 0;
  const server = http.createServer((req, res) => {
    requests += 1;
    req.resume();
    req.on("end", async () => {
      const reply = await respond(req);
      if (reply === null) return;
      const [status, body] = reply;
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(typeof body === "string" ? body : JSON.stringify(body));
    });
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    return await fn(`http://127.0.0.1:${server.address().port}`, () => requests);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
}

async function onlineClient(apiBaseUrl, overrides = {}) {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  const failures = [];
  const sleeps = [];
  const client = new AuthForgeClient({
    appId: "app-id",
    appSecret: "app-secret",
    publicKey: vectors.publicKey,
    onlineHeartbeat: true,
    heartbeatInterval: 3600,
    apiBaseUrl,
    onFailure: (reason, error) => failures.push({ reason, error, authenticated: client.isAuthenticated() }),
    ...overrides,
  });
  client._sleep = async (seconds) => {
    sleeps.push(seconds);
  };
  client._licenseKey = "license-key";
  client._sessionToken = "session.validate.token";
  client._sessionKind = "online";
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) + 3600;
  client._rawPayloadB64 = validateCase.payload;
  client._signature = validateCase.signature;
  client._sessionData = { tier: "pro" };
  client._authenticated = true;
  return { client, failures, sleeps, vectors };
}

/** Run one tick with the interval timer armed; always clears the timer afterwards. */
async function tickWithTimer(client, fn) {
  client._startHeartbeatOnce();
  assert.notEqual(client._heartbeatTimer, null);
  try {
    await client._heartbeatTick();
    await fn();
  } finally {
    client.logout();
  }
}

function onlyFailure(failures) {
  assert.equal(failures.length, 1, JSON.stringify(failures.map((f) => [f.reason, f.error?.code])));
  const [{ reason, error }] = failures;
  assert.equal(reason, "heartbeat_failed");
  assert.ok(error instanceof AuthForgeError);
  return failures[0];
}

function assertInvalidated(client) {
  assert.equal(client.isAuthenticated(), false);
  assert.equal(client.getSessionKind(), null);
  assert.equal(client.getSessionData(), null);
  assert.equal(client._rawPayloadB64, null);
  assert.equal(client._heartbeatStarted, false);
  assert.equal(client._heartbeatTimer, null);
  assert.throws(() => client._gracePeriodCheck(), { message: "missing_local_verification_state" });
}

function assertKept(client) {
  assert.equal(client.isAuthenticated(), true);
  assert.equal(client._sessionToken, "session.validate.token");
  assert.equal(client._heartbeatStarted, true);
  assert.notEqual(client._heartbeatTimer, null);
}

function assertTransient(error, code) {
  assert.equal(error.code, code);
  assert.equal(error.transient, true);
  assert.equal(error.fatal, false);
  assert.equal(isTransientError(error), true);
}

const DEFINITIVE_HEARTBEAT_CODES = [
  ["revoked", 410],
  ["expired", 410],
  ["hwid_mismatch", 403],
  ["blocked", 403],
  ["app_disabled", 403],
  ["session_expired", 401],
  ["invalid_app", 401],
  ["malformed_request", 400],
];

for (const [code, errorStatus] of DEFINITIVE_HEARTBEAT_CODES) {
  for (const status of [errorStatus, 200]) {
    test(`heartbeat ${code} (HTTP ${status}) is definitive and drops the session before onFailure`, async () => {
      await withServer(
        () => [status, { status: "failed", error: code }],
        async (apiBaseUrl, requests) => {
          const { client, failures, sleeps } = await onlineClient(apiBaseUrl);
          await tickWithTimer(client, () => {
            const failure = onlyFailure(failures);
            assert.equal(failure.error.code, code);
            assert.equal(failure.error.message, code);
            assert.equal(failure.error.fatal, true);
            assert.equal(failure.error.transient, false);
            assert.equal(isTransientError(failure.error), false);
            assert.equal(failure.authenticated, false, "session is cleared before onFailure runs");
            assert.equal(requests(), 1, "definitive codes are not retried");
            assert.deepEqual(sleeps, []);
            assertInvalidated(client);
          });
        },
      );
    });
  }
}

test("heartbeat signature_mismatch (tampered success response) is definitive", async () => {
  const vectors = await readVectors();
  const heartbeatCase = vectors.cases.find((item) => item.id === "heartbeat_success");
  const wrongKeyCase = vectors.cases.find((item) => item.id === "wrong_app_key");
  await withServer(
    () => [200, { status: "ok", payload: heartbeatCase.payload, signature: wrongKeyCase.signature }],
    async (apiBaseUrl, requests) => {
      const { client, failures } = await onlineClient(apiBaseUrl);
      client._generateNonce = () => "nonce-heartbeat-001";
      await tickWithTimer(client, () => {
        const { error, authenticated } = onlyFailure(failures);
        assert.equal(error.code, "signature_mismatch");
        assert.equal(error.fatal, true);
        assert.equal(authenticated, false);
        assert.equal(requests(), 1);
        assertInvalidated(client);
      });
    },
  );
});

const TRANSIENT_HEARTBEAT_CODES = [
  ["rate_limited", 429, 3, [2, 5]],
  ["system_error", 500, 1, []],
  ["server_error", 503, 1, []],
  ["no_credits", 429, 1, []],
  ["demo_quota_exceeded", 429, 1, []],
  ["app_burn_cap_reached", 429, 1, []],
  ["bad_request", 400, 1, []],
  ["invalid_key", 401, 1, []],
  ["some_future_code", 400, 1, []],
];

for (const [code, status, expectedRequests, expectedSleeps] of TRANSIENT_HEARTBEAT_CODES) {
  test(`heartbeat ${code} (HTTP ${status}) is transient and keeps the session`, async () => {
    await withServer(
      () => [status, { status: "failed", error: code }],
      async (apiBaseUrl, requests) => {
        const { client, failures, sleeps } = await onlineClient(apiBaseUrl);
        await tickWithTimer(client, () => {
          const failure = onlyFailure(failures);
          assertTransient(failure.error, code);
          assert.equal(failure.error.message, code);
          assert.equal(failure.authenticated, true);
          assert.equal(requests(), expectedRequests);
          assert.deepEqual(sleeps, expectedSleeps);
          assertKept(client);
        });
      },
    );
  });
}

for (const [status, body, code] of [
  [403, "<html>forbidden</html>", "http_error_403"],
  [500, "<html>internal error</html>", "http_error_500"],
  [502, "<html>bad gateway</html>", "http_error_502"],
  [500, "", "http_error_500"],
  [200, "", "invalid_json_response"],
  [200, "[1,2]", "response_not_json_object"],
  [200, '"revoked"', "response_not_json_object"],
  [403, "[]", "http_error_403"],
]) {
  test(`heartbeat HTTP ${status} body ${JSON.stringify(body)} is transient ${code}`, async () => {
    await withServer(
      () => [status, body],
      async (apiBaseUrl, requests) => {
        const { client, failures } = await onlineClient(apiBaseUrl);
        await tickWithTimer(client, () => {
          assertTransient(onlyFailure(failures).error, code);
          assert.equal(requests(), 1);
          assertKept(client);
        });
      },
    );
  });
}

for (const [status, body, expectedMessage] of [
  [403, { error: "revoked" }, /status=null error="revoked"/],
  [200, { error: "revoked" }, /status=null error="revoked"/],
  [403, { status: "revoked" }, /status="revoked" error=null/],
  [410, { status: "failed" }, /status="failed" error=null/],
  [403, { status: "failed", error: "" }, /status="failed" error=""/],
  [403, { status: "failed", error: 42 }, /status="failed" error=42/],
]) {
  test(`heartbeat malformed failure body ${JSON.stringify(body)} (HTTP ${status}) is transient unexpected_response`, async () => {
    await withServer(
      () => [status, body],
      async (apiBaseUrl, requests) => {
        const { client, failures } = await onlineClient(apiBaseUrl);
        await tickWithTimer(client, () => {
          const { error } = onlyFailure(failures);
          assertTransient(error, "unexpected_response");
          assert.match(error.message, /^unexpected_response: /);
          assert.match(error.message, expectedMessage);
          assert.equal(requests(), 1);
          assertKept(client);
        });
      },
    );
  });
}

test("heartbeat network error is transient and reported once", async () => {
  const { client, failures, sleeps } = await onlineClient("http://127.0.0.1:9");
  await tickWithTimer(client, () => {
    const { error } = onlyFailure(failures);
    assertTransient(error, "network_error");
    assert.match(error.message, /^url_error: /);
    assert.deepEqual(sleeps, [2]);
    assertKept(client);
  });
});

test("heartbeat timeout is transient and reported once", async () => {
  await withServer(
    () => null,
    async (apiBaseUrl, requests) => {
      const { client, failures } = await onlineClient(apiBaseUrl, { requestTimeout: 0.2 });
      await tickWithTimer(client, () => {
        assertTransient(onlyFailure(failures).error, "timeout");
        assert.equal(requests(), 2, "one network retry");
        assertKept(client);
      });
    },
  );
});

test("transient heartbeat failure after the session TTL becomes definitive session_expired", async () => {
  await withServer(
    () => [503, { status: "failed", error: "system_error" }],
    async (apiBaseUrl) => {
      const { client, failures } = await onlineClient(apiBaseUrl);
      client._sessionExpiresIn = Math.floor(Date.now() / 1000) - 1;
      await tickWithTimer(client, () => {
        const { error, authenticated } = onlyFailure(failures);
        assert.equal(error.code, "session_expired");
        assert.equal(error.fatal, true);
        assert.equal(error.cause.code, "system_error");
        assert.equal(authenticated, false);
        assertInvalidated(client);
      });
    },
  );
});

test("heartbeat success after a transient failure refreshes the session", async () => {
  let calls = 0;
  const vectors = await readVectors();
  const heartbeatCase = vectors.cases.find((item) => item.id === "heartbeat_success");
  await withServer(
    () => {
      calls += 1;
      return calls <= 1
        ? [503, { status: "failed", error: "system_error" }]
        : [200, { status: "ok", payload: heartbeatCase.payload, signature: heartbeatCase.signature }];
    },
    async (apiBaseUrl) => {
      const { client, failures } = await onlineClient(apiBaseUrl);
      client._generateNonce = () => "nonce-heartbeat-001";
      await tickWithTimer(client, async () => {
        assertTransient(onlyFailure(failures).error, "system_error");
        assertKept(client);
        await client._heartbeatTick();
        assert.equal(failures.length, 1);
        assert.equal(client.isAuthenticated(), true);
        assert.equal(client._sessionToken, "session.heartbeat.token");
        assert.equal(client._sessionExpiresIn, 1900000300);
        assert.notEqual(client._heartbeatTimer, null);
      });
    },
  );
});

test("grace period expiry is definitive session_expired and drops the session", async () => {
  const { client, failures } = await onlineClient("http://127.0.0.1:9", { onlineHeartbeat: false });
  client._sessionExpiresIn = Math.floor(Date.now() / 1000) - 1;
  client._postJson = async () => {
    throw new Error("grace period must not use the network");
  };
  await tickWithTimer(client, () => {
    const { error, authenticated } = onlyFailure(failures);
    assert.equal(error.code, "session_expired");
    assert.equal(error.fatal, true);
    assert.equal(authenticated, false);
    assertInvalidated(client);
  });
});

for (const [label, code, status] of [
  ["transient", "system_error", 500],
  ["definitive", "revoked", 410],
]) {
  test(`onFailure may call logout() and isAuthenticated() on a ${label} heartbeat failure`, async () => {
    await withServer(
      () => [status, { status: "failed", error: code }],
      async (apiBaseUrl) => {
        const seen = [];
        let client;
        ({ client } = await onlineClient(apiBaseUrl, {
          onFailure: (reason, error) => {
            seen.push(["before", reason, error.code, client.isAuthenticated()]);
            client.logout();
            seen.push(["after", client.isAuthenticated()]);
          },
        }));
        await tickWithTimer(client, () => {
          assert.deepEqual(seen, [
            ["before", "heartbeat_failed", code, label === "transient"],
            ["after", false],
          ]);
          assertInvalidated(client);
        });
      },
    );
  });
}

test("onFailure may login() again after a definitive heartbeat failure", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  await withServer(
    (req) =>
      req.url === "/auth/validate"
        ? [200, { status: "ok", payload: validateCase.payload, signature: validateCase.signature }]
        : [403, { status: "failed", error: "hwid_mismatch" }],
    async (apiBaseUrl) => {
      let client;
      let relogin = null;
      ({ client } = await onlineClient(apiBaseUrl, {
        onFailure: (reason, error) => {
          assert.equal(error.code, "hwid_mismatch");
          assert.equal(client.isAuthenticated(), false);
          relogin = client.login("license-key");
        },
      }));
      client._generateNonce = () => "nonce-validate-001";
      await tickWithTimer(client, async () => {
        assert.ok(relogin);
        assert.equal(await relogin, true);
        assert.equal(client.isAuthenticated(), true);
        assert.equal(client._sessionToken, "session.validate.token");
        assert.notEqual(client._heartbeatTimer, null);
      });
    },
  );
});

test("logout() while a heartbeat is in flight leaves the client logged out", async () => {
  const vectors = await readVectors();
  const heartbeatCase = vectors.cases.find((item) => item.id === "heartbeat_success");
  let received;
  const requestReceived = new Promise((resolve) => {
    received = resolve;
  });
  await withServer(
    async () => {
      received();
      await new Promise((resolve) => setTimeout(resolve, 200));
      return [200, { status: "ok", payload: heartbeatCase.payload, signature: heartbeatCase.signature }];
    },
    async (apiBaseUrl) => {
      const { client, failures } = await onlineClient(apiBaseUrl);
      client._generateNonce = () => "nonce-heartbeat-001";
      client._startHeartbeatOnce();
      const tick = client._heartbeatTick();
      await requestReceived;
      client.logout();
      await tick;
      assert.deepEqual(failures, []);
      assert.equal(client.isAuthenticated(), false);
      assert.equal(client._sessionToken, null);
      assert.equal(client._sessionKind, null);
      assert.equal(client._heartbeatTimer, null);
    },
  );
});

test("a heartbeat verdict that lands after a new login() does not touch the new session", async () => {
  const vectors = await readVectors();
  const validateCase = vectors.cases.find((item) => item.id === "validate_success");
  let received;
  const heartbeatReceived = new Promise((resolve) => {
    received = resolve;
  });
  await withServer(
    async (req) => {
      if (req.url === "/auth/validate") {
        return [200, { status: "ok", payload: validateCase.payload, signature: validateCase.signature }];
      }
      received();
      await new Promise((resolve) => setTimeout(resolve, 300));
      return [410, { status: "failed", error: "revoked" }];
    },
    async (apiBaseUrl) => {
      const { client, failures } = await onlineClient(apiBaseUrl);
      client._generateNonce = () => "nonce-validate-001";
      const tick = client._heartbeatTick();
      await heartbeatReceived;
      try {
        assert.equal(await client.login("license-key"), true);
        await tick;
        assert.deepEqual(failures, []);
        assert.equal(client.isAuthenticated(), true);
        assert.equal(client._sessionToken, "session.validate.token");
        assert.notEqual(client._heartbeatTimer, null);
      } finally {
        client.logout();
      }
    },
  );
});

test("isTransientError: only the definitive allowlist is fatal", () => {
  assert.deepEqual([...definitiveErrorCodes].sort(), [
    "app_disabled",
    "blocked",
    "expired",
    "hwid_mismatch",
    "invalid_app",
    "malformed_request",
    "revoked",
    "session_expired",
    "signature_mismatch",
  ]);
  for (const code of definitiveErrorCodes) {
    assert.equal(isTransientError(code), false, code);
    assert.equal(isTransientError(new AuthForgeError(code)), false, code);
    assert.equal(new AuthForgeError(code).fatal, true, code);
  }
  for (const code of transientErrorCodes) {
    assert.equal(isTransientError(code), true, code);
    assert.equal(definitiveErrorCodes.includes(code), false, code);
  }
  for (const code of [
    "network_error",
    "timeout",
    "rate_limited",
    "system_error",
    "no_credits",
    "demo_quota_exceeded",
    "app_burn_cap_reached",
    "bad_request",
    "invalid_key",
    "unexpected_response",
    "unknown_error",
    "some_future_code",
    "http_error_403",
    "http_error_404",
    "http_error_503",
    "",
  ]) {
    assert.equal(isTransientError(code), true, code);
  }
  for (const value of [null, undefined, 42, new Error("revoked"), { code: "revoked" }]) {
    assert.equal(isTransientError(value), true, String(value));
  }
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
    appSecret: "",
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
    // Explicit-license selfBan is an online API; this test covers that
    // dual-mode path. Offline-only clients omit the secret entirely.
    appSecret: "online-selfban",
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
    appSecret: "",
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
      appSecret: "",
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
      appSecret: "",
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

test("offline-only client may omit appSecret; login still requires it", async () => {
  const vectors = await readOfflineVectors();
  const c = lifetimeCase(vectors);
  const client = new AuthForgeClient({
    appId: c.appId,
    publicKey: c.publicKey,
    hwidOverride: c.hwid,
    onFailure: () => {},
  });
  assert.equal(client.appSecret, "");
  assert.equal(client.loginFromFile(c.file), true);
  client.logout();
  await assert.rejects(client.login("XXXX-XXXX-XXXX-XXXX"), {
    message: "appSecret is required for online APIs; omit it only when using loginFromFile",
  });
});

// ---------------------------------------------------------------------------
// Activation requests (`.authforge-request`)
// ---------------------------------------------------------------------------

test("SDK_TAG version matches package.json", async () => {
  const src = await readFile(path.join(here, "authforge.mjs"), "utf8");
  const pkg = JSON.parse(await readFile(path.join(here, "package.json"), "utf8"));
  const match = src.match(/^const SDK_TAG = "node\/([^"]+)";$/m);
  assert.ok(match, "SDK_TAG constant not found");
  assert.equal(match[1], pkg.version);
});

test("createActivationRequest matches committed vectors for the same inputs", async () => {
  const raw = await readFile(path.join(here, "activation_request_vectors.json"), "utf8");
  const vectors = JSON.parse(raw);
  const dummyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  for (const c of vectors.cases) {
    if (!c.inputs) continue;
    const client = new AuthForgeClient({
      appId: c.inputs.appId,
      publicKey: dummyKey,
      hwidOverride: c.inputs.hwid,
    });
    const got = client.createActivationRequest({
      createdAt: c.inputs.createdAt,
      omitOs: !c.inputs.os,
      omitSdk: !c.inputs.sdk,
      includeMachineName: Boolean(c.inputs.machineName),
      machineName: c.inputs.machineName,
      os: c.inputs.os,
      sdk: c.inputs.sdk,
      licenseKey: c.inputs.licenseKey ?? "",
    });
    assert.equal(got, c.file, c.name);
    assert.equal(formatActivationRequest(c.inputs), c.file, `${c.name} formatActivationRequest`);
  }
});

test("createActivationRequest works with no app secret and before login", () => {
  const client = new AuthForgeClient({
    appId: "test-app",
    publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    hwidOverride: "testhwid",
  });
  const file = client.createActivationRequest({
    createdAt: "2026-09-11T12:00:00.000Z",
    omitOs: true,
    omitSdk: true,
  });
  assert.match(file, /BEGIN AUTHFORGE ACTIVATION REQUEST/);
  assert.equal(file.includes("BEGIN AUTHFORGE LICENSE"), false);
  assert.equal(file.includes("machineName"), false);
});

test("writeActivationRequest writes UTF-8 next to the app", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "authforge-request-"));
  try {
    const dest = path.join(dir, "machine.authforge-request");
    const client = new AuthForgeClient({
      appId: "test-app",
      publicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      hwidOverride: "testhwid",
    });
    client.writeActivationRequest(dest, {
      createdAt: "2026-09-11T12:00:00.000Z",
      omitOs: true,
      omitSdk: true,
    });
    const written = await readFile(dest, "utf8");
    assert.equal(written, client.createActivationRequest({
      createdAt: "2026-09-11T12:00:00.000Z",
      omitOs: true,
      omitSdk: true,
    }));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
