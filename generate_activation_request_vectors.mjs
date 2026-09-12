/**
 * Generates `activation_request_vectors.json` - the cross-SDK conformance
 * vectors for `.authforge-request` activation requests.
 *
 * Good cases are produced by `formatActivationRequest` in this SDK so the
 * generator cannot drift from the encoder the client uses. Corrupted cases
 * (checksum, truncation, license-file confusion, CRLF/BOM/preamble) exercise
 * the dashboard parser.
 */
import { writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { formatActivationRequest } from "./authforge.mjs";

const APP_ID = "test-app";
const HWID = "testhwid";
const CREATED_AT = "2026-09-11T12:00:00.000Z";

const MINIMAL_INPUTS = { appId: APP_ID, hwid: HWID, createdAt: CREATED_AT };
const FULL_INPUTS = {
  appId: APP_ID,
  hwid: HWID,
  createdAt: CREATED_AT,
  machineName: "dev-box",
  os: "Windows 11",
  // Frozen fixture that pins the *encoding*, not the live SDK tag. Do not
  // wire this to SDK_TAG / package.json: a version bump must not invalidate
  // the golden file in seven repos.
  sdk: "python/0.0.0-vectors",
  licenseKey: "TEST-KEY0-0000-0000",
};

function wrapPreamble(file) {
  const begin = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----";
  const end = "-----END AUTHFORGE ACTIVATION REQUEST-----";
  const normalized = file.replace(/\r\n?/g, "\n");
  const start = normalized.indexOf(begin);
  const stop = normalized.indexOf(end);
  const armor = normalized.slice(start, stop + end.length);
  const lines = armor.split("\n");
  const blank = lines.findIndex((l) => l === "");
  const headers = lines.slice(0, blank + 1);
  const body = lines.slice(blank + 1, lines.length - 1).join("");
  const rewrapped = [];
  for (let i = 0; i < body.length; i += 20) rewrapped.push(body.slice(i, i + 20));
  const rebuilt = [...headers, ...rewrapped, end].join("\r\n");
  return `\uFEFFPlease see attached.\r\n${rebuilt}\r\nThanks,\r\nPat\r\n`;
}

function build() {
  const goodMinimal = formatActivationRequest(MINIMAL_INPUTS);
  const goodFull = formatActivationRequest(FULL_INPUTS);
  const mangledChecksum = goodMinimal.replace(/Checksum: [0-9a-f]+/, "Checksum: deadbeefdeadbeef");
  const truncated = goodMinimal.replace(/[A-Za-z0-9+/]{12}(?=\n-----END)/, "");
  const licenseFile =
    "-----BEGIN AUTHFORGE LICENSE-----\nVersion: 1\nApp-Id: test-app\n\nQUJD\n-----END AUTHFORGE LICENSE-----\n";

  return {
    format: "authforge-activation-request",
    version: 1,
    description:
      "Cross-SDK conformance vectors for activation requests (.authforge-request). Generators with the same inputs must match good_minimal and good_full byte-for-byte. Parser tolerance: CRLF, UTF-8 BOM, re-wrapping, email preamble. Checksum is decision-relevant.",
    cases: [
      {
        name: "good_minimal",
        expect: "ok",
        inputs: MINIMAL_INPUTS,
        file: goodMinimal,
      },
      {
        name: "good_full",
        expect: "ok",
        inputs: FULL_INPUTS,
        file: goodFull,
      },
      {
        name: "tolerate_crlf_bom_preamble",
        expect: "ok",
        file: wrapPreamble(goodMinimal),
      },
      {
        name: "bad_checksum",
        expect: "checksum_mismatch",
        file: mangledChecksum,
      },
      {
        name: "truncated_body",
        expect: "reject",
        file: truncated,
      },
      {
        name: "license_file",
        expect: "is_license_file",
        file: licenseFile,
      },
    ],
  };
}

async function main() {
  const vectors = build();
  const here = path.dirname(fileURLToPath(import.meta.url));
  const outputPath = path.join(here, "activation_request_vectors.json");
  await writeFile(outputPath, JSON.stringify(vectors, null, 2) + "\n", "utf8");
  console.log(outputPath);
}

main();
