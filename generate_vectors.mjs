import { createHash, createHmac } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const APP_SECRET = "af_test_secret_2026_reference";
const SIG_KEY = "af_test_sig_key_2026_reference_0123456789abcdef";
const NONCE = "0123456789abcdeffedcba9876543210";
const SESSION_SIGNING_SECRET = "authforge-dev-session-signing-secret-rotate-before-production";
const EXPIRES_IN = 1740433200;
const TIMESTAMP = 1740429600;
const APP_ID = "test-app";
const LICENSE_KEY = "test-key";
const HWID = "testhwid";

function b64urlNoPad(data) {
  return Buffer.from(data).toString("base64url");
}

function buildSessionToken() {
  const body = {
    appId: APP_ID,
    licenseKey: LICENSE_KEY,
    hwid: HWID,
    sigKey: SIG_KEY,
    expiresIn: EXPIRES_IN,
  };
  const bodyJson = JSON.stringify(body);
  const bodyB64 = b64urlNoPad(Buffer.from(bodyJson, "utf8"));
  const digest = createHmac("sha256", Buffer.from(SESSION_SIGNING_SECRET, "utf8"))
    .update(Buffer.from(bodyB64, "utf8"))
    .digest();
  const sigB64 = b64urlNoPad(digest);
  return `${bodyB64}.${sigB64}`;
}

function buildPayloadB64() {
  const payloadObject = {
    sessionToken: buildSessionToken(),
    timestamp: TIMESTAMP,
    expiresIn: EXPIRES_IN,
    nonce: NONCE,
  };
  const payloadJson = JSON.stringify(payloadObject);
  return Buffer.from(payloadJson, "utf8").toString("base64");
}

async function main() {
  const payload = buildPayloadB64();

  const validateKey = createHash("sha256").update(`${APP_SECRET}${NONCE}`, "utf8").digest();
  const validateSig = createHmac("sha256", validateKey).update(payload, "utf8").digest("hex");

  const heartbeatKey = createHash("sha256").update(`${SIG_KEY}${NONCE}`, "utf8").digest();
  const heartbeatSig = createHmac("sha256", heartbeatKey).update(payload, "utf8").digest("hex");

  const vectors = {
    validate: {
      algorithm: {
        keyDerivation: "SHA256(appSecret + nonce)",
        signature: "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
      },
      inputs: {
        appSecret: APP_SECRET,
        nonce: NONCE,
        payload,
      },
      outputs: {
        derivedKeyHex: validateKey.toString("hex"),
        signatureHex: validateSig,
      },
    },
    heartbeat: {
      algorithm: {
        keyDerivation: "SHA256(sigKey + nonce)",
        signature: "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
      },
      inputs: {
        sigKey: SIG_KEY,
        nonce: NONCE,
        payload,
      },
      outputs: {
        derivedKeyHex: heartbeatKey.toString("hex"),
        signatureHex: heartbeatSig,
      },
    },
  };

  const here = path.dirname(fileURLToPath(import.meta.url));
  const outputPath = path.join(here, "test_vectors.json");
  await writeFile(outputPath, JSON.stringify(vectors, null, 2), "utf8");
  console.log(outputPath);
}

main();
