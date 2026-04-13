import { createHash, createHmac } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const APP_SECRET = "af_test_secret_2026_reference";
const NONCE = "0123456789abcdeffedcba9876543210";
const SESSION_SIGNING_SECRET = "authforge-dev-session-signing-secret-rotate-before-production";

function b64urlNoPad(data) {
  return Buffer.from(data).toString("base64url");
}

function buildRealisticSessionToken() {
  const body = {
    appId: "test-app",
    licenseKey: "test-key",
    hwid: "testhwid",
    appSecret: APP_SECRET,
    expiresIn: 1740433200,
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
    sessionToken: buildRealisticSessionToken(),
    timestamp: 1740429600,
    expiresIn: 1740433200,
    nonce: NONCE,
  };
  const payloadJson = JSON.stringify(payloadObject);
  return Buffer.from(payloadJson, "utf8").toString("base64");
}

const PAYLOAD = buildPayloadB64();

async function main() {
  const derivedKeyBytes = createHash("sha256").update(`${APP_SECRET}${NONCE}`, "utf8").digest();
  const signatureHex = createHmac("sha256", derivedKeyBytes)
    .update(PAYLOAD, "utf8")
    .digest("hex");

  const vectors = {
    algorithm: {
      keyDerivation: "SHA256(appSecret + nonce)",
      signature: "HMAC-SHA256(raw_base64_payload_string, derivedKey)",
    },
    inputs: {
      appSecret: APP_SECRET,
      nonce: NONCE,
      payload: PAYLOAD,
    },
    outputs: {
      derivedKeyHex: derivedKeyBytes.toString("hex"),
      signatureHex,
    },
  };

  const here = path.dirname(fileURLToPath(import.meta.url));
  const outputPath = path.join(here, "test_vectors.json");
  await writeFile(outputPath, JSON.stringify(vectors, null, 2), "utf8");
  console.log(outputPath);
}

main();
