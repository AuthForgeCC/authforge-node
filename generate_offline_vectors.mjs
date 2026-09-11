/**
 * Generates `offline_license_vectors.json` - the cross-SDK conformance
 * vectors for cloud-minted offline license files (`.authforge`).
 *
 * Every SDK ships a byte-identical copy of the output and runs its own
 * verifier against each case (see the vectors-parity CI job in the SDK
 * monorepo). The key material below is a fixed, publicly-known TEST seed;
 * it must never be used for anything else.
 *
 * Format recap (version 1):
 *
 *   -----BEGIN AUTHFORGE LICENSE-----
 *   Version: 1
 *   App-Id: <appId>
 *   License: <licenseKey>
 *   Key-Id: <kid>
 *   Expires-At: <ISO | never>
 *
 *   <base64 JSON payload, wrapped at 64 cols>
 *   -----END AUTHFORGE LICENSE-----
 *   -----BEGIN AUTHFORGE SIGNATURE-----
 *   <base64 Ed25519 signature>
 *   -----END AUTHFORGE SIGNATURE-----
 *
 * Signed bytes: UTF-8 of the base64 payload string (body lines joined,
 * whitespace removed) - the same contract as /auth/validate responses.
 */
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

// PKCS#8 DER prefix for an Ed25519 private key followed by the 32-byte seed.
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
const OTHER_APP_ID = "other-app";
const LICENSE_KEY = "TEST-KEY0-0000-0000";
const KID = "kid-test-0001";
const HWID = "testhwid";
const OTHER_HWID = "otherhwid";
const NOW = "2026-09-11T12:00:00.000Z";
const ISSUED_AT = "2026-09-11T11:00:00.000Z";
const FUTURE = "2027-01-01T00:00:00.000Z";
const PAST = "2026-09-11T11:59:59.000Z";

function wrap64(value) {
  const lines = [];
  for (let i = 0; i < value.length; i += 64) lines.push(value.slice(i, i + 64));
  return lines.join("\n");
}

function armor({ payloadBase64, signatureBase64, appId, licenseKey, kid, expiresAt }) {
  return [
    "-----BEGIN AUTHFORGE LICENSE-----",
    "Version: 1",
    `App-Id: ${appId}`,
    `License: ${licenseKey}`,
    `Key-Id: ${kid}`,
    `Expires-At: ${expiresAt === null ? "never" : expiresAt}`,
    "",
    wrap64(payloadBase64),
    "-----END AUTHFORGE LICENSE-----",
    "-----BEGIN AUTHFORGE SIGNATURE-----",
    wrap64(signatureBase64),
    "-----END AUTHFORGE SIGNATURE-----",
    "",
  ].join("\n");
}

function mint(payloadObject, privateKey = SIGNING.privateKey) {
  const payloadBase64 = Buffer.from(JSON.stringify(payloadObject), "utf8").toString("base64");
  const signatureBase64 = sign(null, Buffer.from(payloadBase64, "utf8"), privateKey).toString("base64");
  const file = armor({
    payloadBase64,
    signatureBase64,
    appId: payloadObject.appId,
    licenseKey: payloadObject.licenseKey,
    kid: payloadObject.kid,
    expiresAt: payloadObject.expiresAt,
  });
  return { file, payloadBase64, signatureBase64 };
}

function basePayload(overrides = {}) {
  return {
    v: 1,
    typ: "authforge-license",
    appId: APP_ID,
    licenseKey: LICENSE_KEY,
    jti: "00000000-0000-4000-8000-000000000001",
    kid: KID,
    issuedAt: ISSUED_AT,
    expiresAt: FUTURE,
    hwid: { mode: "bound", hwids: [HWID, "second-machine"] },
    label: "Vector license",
    licenseExpiresAt: null,
    licenseVariables: { tier: "pro", seats: 3, beta: true },
    appVariables: { theme: "dark" },
    ...overrides,
  };
}

function tamperBody(file, payloadBase64) {
  // Flip one character inside the base64 body so the signature no longer matches.
  const firstLine = payloadBase64.slice(0, 64);
  const idx = 10;
  const original = firstLine[idx];
  const replacement = original === "A" ? "B" : "A";
  const tampered = firstLine.slice(0, idx) + replacement + firstLine.slice(idx + 1);
  return file.replace(firstLine, tampered);
}

function rewrap(file, width) {
  return file
    .split("\n")
    .map((line) => (/^[A-Za-z0-9+/=]{20,}$/.test(line) ? line.match(new RegExp(`.{1,${width}}`, "g")).join("\n") : line))
    .join("\n");
}

function build() {
  const good = mint(basePayload());
  const anyMachine = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000002", hwid: { mode: "any" } }));
  const lifetime = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000003", expiresAt: null }));
  const expired = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000004", expiresAt: PAST }));
  const wrongApp = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000005", appId: OTHER_APP_ID }));
  const wrongKey = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000006" }), WRONG.privateKey);
  const v2 = mint(basePayload({ jti: "00000000-0000-4000-8000-000000000007", v: 2 }));
  // `true == 1` in Python; every SDK must demand a JSON *number* for `v`.
  const vBool = mint(basePayload({ jti: "00000000-0000-4000-8000-00000000000a", v: true }));
  const missingExpiresAt = mint({
    v: 1,
    typ: "authforge-license",
    appId: APP_ID,
    licenseKey: LICENSE_KEY,
    jti: "00000000-0000-4000-8000-000000000009",
    kid: KID,
    issuedAt: ISSUED_AT,
    hwid: { mode: "any" },
  });
  const minimal = mint({
    v: 1,
    typ: "authforge-license",
    appId: APP_ID,
    licenseKey: LICENSE_KEY,
    jti: "00000000-0000-4000-8000-000000000008",
    kid: KID,
    issuedAt: ISSUED_AT,
    expiresAt: FUTURE,
    hwid: { mode: "bound", hwids: [HWID] },
  });

  const common = { appId: APP_ID, publicKey: SIGNING.rawPublicKeyBase64, hwid: HWID, now: NOW };

  const cases = [
    {
      name: "good_bound",
      description: "Well-formed file, right key, right app, unexpired, HWID in bound list.",
      ...common,
      file: good.file,
      expect: "ok",
      payloadBase64: good.payloadBase64,
      signatureBase64: good.signatureBase64,
      payload: basePayload(),
    },
    {
      name: "good_bound_second_hwid",
      description: "Same file verifies on the second bound HWID.",
      ...common,
      hwid: "second-machine",
      file: good.file,
      expect: "ok",
    },
    {
      name: "good_any_machine",
      description: "mode:any file verifies on any HWID (even an empty one).",
      ...common,
      hwid: "",
      file: anyMachine.file,
      expect: "ok",
    },
    {
      name: "good_lifetime",
      description: "expiresAt:null never expires.",
      ...common,
      now: "2099-01-01T00:00:00.000Z",
      file: lifetime.file,
      expect: "ok",
    },
    {
      name: "good_minimal_payload",
      description: "Optional fields absent; still valid.",
      ...common,
      file: minimal.file,
      expect: "ok",
    },
    {
      name: "good_crlf_rewrapped_with_junk",
      description: "CRLF line endings, body re-wrapped at 17 columns, BOM and text around the armor.",
      ...common,
      file: `\uFEFFForwarded license file\r\n${rewrap(good.file, 17).replace(/\n/g, "\r\n")}\r\n-- end --\r\n`,
      expect: "ok",
    },
    {
      name: "good_key_rotation_list",
      description: "Public key list where only the second entry matches.",
      ...common,
      publicKey: `${WRONG.rawPublicKeyBase64},${SIGNING.rawPublicKeyBase64}`,
      file: good.file,
      expect: "ok",
    },
    {
      name: "bad_signature_tampered_body",
      description: "One base64 character flipped in the payload body.",
      ...common,
      file: tamperBody(good.file, good.payloadBase64),
      expect: "bad_signature",
    },
    {
      name: "bad_signature_wrong_key",
      description: "Signed by a different (wrong) app key.",
      ...common,
      file: wrongKey.file,
      expect: "bad_signature",
    },
    {
      name: "bad_signature_verifier_has_wrong_key",
      description: "Good file, but the verifier is configured with the wrong public key.",
      ...common,
      publicKey: WRONG.rawPublicKeyBase64,
      file: good.file,
      expect: "bad_signature",
    },
    {
      name: "wrong_app",
      description: "Valid signature but payload appId differs from the configured app.",
      ...common,
      file: wrongApp.file,
      expect: "wrong_app",
    },
    {
      name: "expired",
      description: "expiresAt one second before now.",
      ...common,
      file: expired.file,
      expect: "expired",
    },
    {
      name: "expired_exactly_now",
      description: "expiresAt == now is expired (strict).",
      ...common,
      now: FUTURE,
      file: good.file,
      expect: "expired",
    },
    {
      name: "hwid_mismatch",
      description: "Local HWID not in the bound list.",
      ...common,
      hwid: OTHER_HWID,
      file: good.file,
      expect: "hwid_mismatch",
    },
    {
      name: "hwid_mismatch_empty_hwid",
      description: "Bound file with an empty local HWID is a mismatch.",
      ...common,
      hwid: "",
      file: good.file,
      expect: "hwid_mismatch",
    },
    {
      name: "unsupported_version",
      description: "Signed payload declares v:2.",
      ...common,
      file: v2.file,
      expect: "unsupported_version",
    },
    {
      name: "unsupported_version_bool",
      description: "Signed payload declares v:true. JSON booleans are not version numbers even where true == 1 (Python).",
      ...common,
      file: vBool.file,
      expect: "unsupported_version",
    },
    {
      name: "malformed_payload_missing_expires_at",
      description: "Well-signed v1 payload with no expiresAt field (null would mean lifetime; absence is malformed).",
      ...common,
      file: missingExpiresAt.file,
      expect: "malformed_payload",
    },
    {
      name: "bad_armor_garbage",
      ...common,
      file: "this is not a license file",
      expect: "bad_armor",
    },
    {
      name: "bad_armor_missing_signature_block",
      ...common,
      file: good.file.split("-----BEGIN AUTHFORGE SIGNATURE-----")[0],
      expect: "bad_armor",
    },
    {
      name: "bad_armor_no_blank_line",
      ...common,
      file: good.file.replace("Expires-At: " + FUTURE + "\n\n", "Expires-At: " + FUTURE + "\n"),
      expect: "bad_armor",
    },
    {
      name: "bad_armor_empty",
      ...common,
      file: "",
      expect: "bad_armor",
    },
  ];

  return {
    format: "authforge-license-file",
    version: 1,
    description:
      "Cross-SDK conformance vectors for offline .authforge license files. Verify order: bad_armor -> bad_signature -> unsupported_version -> malformed_payload -> wrong_app -> expired -> hwid_mismatch. Signature is Ed25519 over the UTF-8 bytes of the base64 payload string.",
    keys: {
      signingPublicKey: SIGNING.rawPublicKeyBase64,
      wrongPublicKey: WRONG.rawPublicKeyBase64,
      note: "Raw 32-byte Ed25519 public keys, standard base64 - same as the dashboard shows.",
    },
    cases,
  };
}

async function main() {
  const vectors = build();
  const here = path.dirname(fileURLToPath(import.meta.url));
  const outputPath = path.join(here, "offline_license_vectors.json");
  await writeFile(outputPath, JSON.stringify(vectors, null, 2) + "\n", "utf8");
  console.log(outputPath);
}

main();
