// deno test supabase/functions/_shared/playIntegrity_test.ts
//
// Covers `evaluateVerdict` — every decision made about a decoded token — and
// the request-hash encoding the Android app has to match. Decoding itself is
// a call to Google and isn't exercised here; the payloads below follow the
// shape documented at
// https://developer.android.com/google/play/integrity/verdicts.

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import {
  ANDROID_PACKAGE_NAME,
  evaluateVerdict,
  expectedRequestHash,
  PlayIntegrityError,
} from "./playIntegrity.ts";

const NOW = 1_800_000_000_000;
const HASH = "aGFzaC1vZi10aGUtcGhvdG8";

/// A verdict for a Play-installed build on a genuine device, made over `HASH`
/// a few seconds ago. Each test overrides the one part it's about.
// deno-lint-ignore no-explicit-any
function payload(overrides: Record<string, any> = {}): Record<string, any> {
  return {
    requestDetails: {
      requestPackageName: ANDROID_PACKAGE_NAME,
      requestHash: HASH,
      timestampMillis: String(NOW - 5_000),
    },
    appIntegrity: {
      appRecognitionVerdict: "PLAY_RECOGNIZED",
      packageName: ANDROID_PACKAGE_NAME,
      certificateSha256Digest: ["6a6a1474b5cbbb2b1aa57e0bc3"],
      versionCode: "42",
    },
    deviceIntegrity: { deviceRecognitionVerdict: ["MEETS_DEVICE_INTEGRITY"] },
    accountDetails: { appLicensingVerdict: "LICENSED" },
    ...overrides,
  };
}

const params = { expectedRequestHash: HASH, now: NOW };

Deno.test("a Play-recognized build on a genuine device passes", () => {
  evaluateVerdict(payload(), params);
});

Deno.test("timestampMillis is accepted as a number as well as a string", () => {
  const p = payload();
  p.requestDetails.timestampMillis = NOW - 5_000;
  evaluateVerdict(p, params);
});

Deno.test("a token made over different bytes is refused", () => {
  assertThrows(
    () => evaluateVerdict(payload(), { ...params, expectedRequestHash: "c29tZS1vdGhlci1waG90bw" }),
    PlayIntegrityError,
    "request hash",
  );
});

Deno.test("a token with no request hash is refused", () => {
  const p = payload();
  delete p.requestDetails.requestHash;
  assertThrows(() => evaluateVerdict(p, params), PlayIntegrityError, "request hash");
});

Deno.test("a token requested by another package is refused", () => {
  const p = payload();
  p.requestDetails.requestPackageName = "com.example.lookalike";
  assertThrows(() => evaluateVerdict(p, params), PlayIntegrityError, "different package");
});

Deno.test("a stale token is refused", () => {
  const p = payload();
  p.requestDetails.timestampMillis = String(NOW - 11 * 60 * 1000);
  assertThrows(() => evaluateVerdict(p, params), PlayIntegrityError, "too old");
});

Deno.test("a token dated in the future is refused", () => {
  const p = payload();
  p.requestDetails.timestampMillis = String(NOW + 10 * 60 * 1000);
  assertThrows(() => evaluateVerdict(p, params), PlayIntegrityError, "future");
});

Deno.test("a sideloaded or modified build is refused", () => {
  for (const verdict of ["UNRECOGNIZED_VERSION", "UNEVALUATED", undefined]) {
    const p = payload();
    p.appIntegrity.appRecognitionVerdict = verdict;
    assertThrows(() => evaluateVerdict(p, params), PlayIntegrityError, "not Play-recognized");
  }
});

Deno.test("an emulator or compromised device is refused", () => {
  // An empty verdict is what an emulator gets; basic integrity alone is a
  // device that only passes the weakest check.
  for (const verdicts of [[], ["MEETS_BASIC_INTEGRITY"], undefined]) {
    assertThrows(
      () => evaluateVerdict(payload({ deviceIntegrity: { deviceRecognitionVerdict: verdicts } }), params),
      PlayIntegrityError,
      "device integrity",
    );
  }
});

Deno.test("a payload that isn't a verdict at all is refused, not crashed on", () => {
  for (const junk of [undefined, null, "token", [], {}, { requestDetails: null }]) {
    assertThrows(() => evaluateVerdict(junk, params), PlayIntegrityError);
  }
});

Deno.test("the request hash is SHA-256 of the body, base64url without padding", async () => {
  // SHA-256("abc"), the FIPS 180 test vector. Its standard base64 form ends
  // in "=" and contains "/" — both of which must be gone here, since the
  // Android app sends the URL-safe unpadded form.
  assertEquals(
    await expectedRequestHash(new TextEncoder().encode("abc")),
    "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
  );
});
