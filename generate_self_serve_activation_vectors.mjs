/**
 * Generates `self_serve_activation_vectors.json` - the cross-SDK conformance
 * vectors for self-serve offline activation (`POST /auth/offline/activate`).
 *
 * Every SDK ships a byte-identical copy of the output and runs its
 * `activate_offline` against each case with a mocked HTTP server that answers
 * `response.status` / `response.body`. The key material is the same fixed,
 * publicly-known TEST seed as `generate_offline_vectors.mjs`; it must never be
 * used for anything else.
 *
 * Server contract (platform/backend/docs/offline-self-serve-activation.md):
 *
 *   POST /auth/offline/activate
 *   { appId, appSecret, licenseKey, hwid, nonce }
 *   201 { status: "success", file, fileName, jti, replay: false }   new machine, 2 credits
 *   200 { status: "success", file, fileName, jti, replay: true }    same machine, free
 *   4xx/5xx { status: "failed", error }
 *
 * The SDK must verify `file` with its offline verifier (configured public
 * key, configured app id, local HWID) BEFORE writing it, and must never write
 * a file that fails. Local verification failures surface as the SDK code
 * `offline_file_rejected` (fatal), never as the verifier's own code, so an app
 * can tell "the server refused" (`hwid_mismatch`: no free seat) from "the
 * server sent a file this machine cannot use".
 */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

function keyPairFromSeed(seedHex) {
  const der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(seedHex, "hex")]);
  const privateKey = createPrivateKey({ key: der, format: "der", type: "pkcs8" });
  const publicKey = createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  const rawPublicKeyBase64 = Buffer.from(jwk.x, "base64url").toString("base64");
  return { privateKey, rawPublicKeyBase64 };
}

const SIGNING = keyPairFromSeed("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
const WRONG = keyPairFromSeed("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");

const APP_ID = "test-app";
const APP_SECRET = "test-app-secret";
const LICENSE_KEY = "TEST-KEY0-0000-0000";
const KID = "kid-test-0001";
const HWID = "testhwid";
const OTHER_HWID = "otherhwid";
const ISSUED_AT = "2026-10-09T12:00:00.000Z";
const JTI = "00000000-0000-4000-8000-0000000000a1";

function wrap64(value) {
  const lines = [];
  for (let i = 0; i < value.length; i += 64) lines.push(value.slice(i, i + 64));
  return lines.join("\n");
}

function armor({ payloadBase64, signatureBase64, payload }) {
  return [
    "-----BEGIN AUTHFORGE LICENSE-----",
    "Version: 1",
    `App-Id: ${payload.appId}`,
    `License: ${payload.licenseKey}`,
    `Key-Id: ${payload.kid}`,
    `Expires-At: ${payload.expiresAt === null ? "never" : payload.expiresAt}`,
    "",
    wrap64(payloadBase64),
    "-----END AUTHFORGE LICENSE-----",
    "-----BEGIN AUTHFORGE SIGNATURE-----",
    wrap64(signatureBase64),
    "-----END AUTHFORGE SIGNATURE-----",
    "",
  ].join("\n");
}

/** Field order matches the server's `buildOfflineLicensePayload`. */
function selfServePayload(overrides = {}) {
  return {
    v: 1,
    typ: "authforge-license",
    appId: APP_ID,
    licenseKey: LICENSE_KEY,
    jti: JTI,
    kid: KID,
    issuedAt: ISSUED_AT,
    expiresAt: null,
    hwid: { mode: "bound", hwids: [HWID] },
    licenseExpiresAt: null,
    licenseVariables: { tier: "lifetime" },
    appVariables: { theme: "dark" },
    ...overrides,
  };
}

function mint(payload, privateKey = SIGNING.privateKey) {
  const payloadBase64 = Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
  const signatureBase64 = sign(null, Buffer.from(payloadBase64, "utf8"), privateKey).toString("base64");
  return armor({ payloadBase64, signatureBase64, payload });
}

function tamper(file) {
  // Flip one base64 character in the first body line so the signature fails.
  const lines = file.split("\n");
  const i = lines.indexOf("") + 1;
  const line = lines[i];
  lines[i] = line.slice(0, 10) + (line[10] === "A" ? "B" : "A") + line.slice(11);
  return lines.join("\n");
}

function success(file, replay, status = replay ? 200 : 201) {
  return {
    status,
    body: { status: "success", file, fileName: `${LICENSE_KEY}.authforge`, jti: JTI, replay },
  };
}

function failure(status, error) {
  return { status, body: { status: "failed", error } };
}

function build() {
  const good = mint(selfServePayload());

  const activated = (replay) => ({
    outcome: "activated",
    writesFile: true,
    fileWritten: good,
    replay,
    sessionKind: "offline",
    licenseVariables: { tier: "lifetime" },
    appVariables: { theme: "dark" },
  });
  const rejected = (detail) => ({
    outcome: "error",
    writesFile: false,
    errorCode: "offline_file_rejected",
    fatal: true,
    detail,
  });
  const serverError = (errorCode, fatal) => ({ outcome: "error", writesFile: false, errorCode, fatal });

  const cases = [
    {
      name: "activated_new_machine",
      description: "201: a new file for this machine. Verify, write it, start an offline session.",
      response: success(good, false),
      expect: activated(false),
    },
    {
      name: "activated_replay",
      description: "200: the machine already had a file; the server returns the identical bytes. Same handling as 201.",
      response: success(good, true),
      expect: activated(true),
    },
    {
      name: "reject_tampered_file",
      description: "Signature does not verify. Do not write.",
      response: success(tamper(good), false),
      expect: rejected("bad_signature"),
    },
    {
      name: "reject_wrong_key",
      description: "Signed by a key that is not configured. Do not write.",
      response: success(mint(selfServePayload(), WRONG.privateKey), false),
      expect: rejected("bad_signature"),
    },
    {
      name: "reject_other_hwid",
      description: "Valid signature but bound to a different machine. Do not write.",
      response: success(mint(selfServePayload({ hwid: { mode: "bound", hwids: [OTHER_HWID] } })), false),
      expect: rejected("hwid_mismatch"),
    },
    {
      name: "reject_wrong_app",
      description: "Valid signature but for another app. Do not write.",
      response: success(mint(selfServePayload({ appId: "other-app" })), false),
      expect: rejected("wrong_app"),
    },
    {
      name: "reject_missing_file",
      description: "Success status without a file field. Existing malformed-response handling; do not write.",
      response: { status: 201, body: { status: "success", jti: JTI, replay: false } },
      expect: serverError("unexpected_response", false),
    },
    {
      name: "error_offline_activation_disabled",
      description: "The app has not opted in to self-serve activation.",
      response: failure(403, "offline_activation_disabled"),
      expect: serverError("offline_activation_disabled", true),
    },
    {
      name: "error_offline_activation_requires_perpetual",
      description: "The license has an expiry; only perpetual licenses can self-serve.",
      response: failure(409, "offline_activation_requires_perpetual"),
      expect: serverError("offline_activation_requires_perpetual", true),
    },
    {
      name: "error_offline_activation_requires_seats",
      description: "Unlimited-seat (shared) licenses cannot self-serve.",
      response: failure(409, "offline_activation_requires_seats"),
      expect: serverError("offline_activation_requires_seats", true),
    },
    {
      name: "error_offline_activation_limit_reached",
      description: "Every machine slot on the license is used. HWID resets do not free them; the buyer must contact the vendor.",
      response: failure(403, "offline_activation_limit_reached"),
      expect: serverError("offline_activation_limit_reached", true),
    },
    {
      name: "error_hwid_mismatch",
      description: "No free seat for this machine.",
      response: failure(403, "hwid_mismatch"),
      expect: serverError("hwid_mismatch", true),
    },
    {
      name: "error_revoked",
      description: "Existing code, existing classification.",
      response: failure(410, "revoked"),
      expect: serverError("revoked", true),
    },
    {
      name: "error_invalid_key",
      description: "Existing code, existing classification (transient in every SDK today).",
      response: failure(401, "invalid_key"),
      expect: serverError("invalid_key", false),
    },
    {
      name: "error_no_credits",
      description: "The app owner is out of credits. Existing code, existing classification.",
      response: failure(429, "no_credits"),
      expect: serverError("no_credits", false),
    },
    {
      name: "error_rate_limited",
      description:
        "Existing code. The SDK may retry exactly as login() does for rate_limited; a server that keeps answering this ends in this error.",
      response: failure(429, "rate_limited"),
      expect: serverError("rate_limited", false),
    },
    {
      name: "error_system_error",
      description: "Existing code, existing classification.",
      response: failure(500, "system_error"),
      expect: serverError("system_error", false),
    },
  ];

  return {
    format: "authforge-self-serve-activation",
    version: 1,
    description:
      "Cross-SDK conformance vectors for POST /auth/offline/activate. Mock the server with each case's response, call activate_offline(licenseKey, path) with the config below, and check expect. Every case must also assert the request (method, path, body fields).",
    config: {
      appId: APP_ID,
      appSecret: APP_SECRET,
      publicKey: SIGNING.rawPublicKeyBase64,
      licenseKey: LICENSE_KEY,
      hwid: HWID,
      note: "Use the SDK's HWID override (or test hook) to make the local HWID equal config.hwid.",
    },
    request: {
      method: "POST",
      path: "/auth/offline/activate",
      bodyFields: ["appId", "appSecret", "licenseKey", "hwid", "nonce"],
      note: "Body must carry exactly these fields: appId, appSecret and licenseKey from config, hwid equal to the HWID login() would send, and a fresh nonce from the SDK's existing generator.",
    },
    expectations: {
      activated:
        "Return success, write fileWritten byte-for-byte to path (atomically, creating parent directories), and leave the client authenticated with session kind 'offline' and the listed variables, exactly as login_from_file() would. No heartbeat starts.",
      error:
        "Surface errorCode through the SDK's error type, with fatal/transient as listed. Do not write path, do not modify an existing file at path, do not exit the process, and leave the client unauthenticated.",
      offline_file_rejected:
        "SDK-level code for a success response whose file fails local verification. `detail` is the verifier's reason; include it in the error message.",
    },
    cases,
  };
}

const here = path.dirname(fileURLToPath(import.meta.url));
const out = path.join(here, "self_serve_activation_vectors.json");
await writeFile(out, `${JSON.stringify(build(), null, 2)}\n`, "utf8");
console.log(`wrote ${out}`);
