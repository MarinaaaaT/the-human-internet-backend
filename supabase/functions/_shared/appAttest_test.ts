// deno test --allow-read supabase/functions/_shared/appAttest_test.ts
//
// The attestation cases run against real objects Apple's service produced
// (see testdata/README.md), which is the only way to exercise the real
// certificate chain; the assertion cases add locally generated P-256 keys so
// that tampering can be tested in each direction.

import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { decode as decodeCbor, encode as encodeCbor } from "npm:cbor-x@1";
import * as x509 from "npm:@peculiar/x509@1";
import {
  AppAttestError,
  concat,
  derToRawEcdsaSignature,
  fromBase64,
  sha256,
  toBase64,
  verifyAssertion,
  verifyAttestation,
} from "./appAttest.ts";

const FIXTURE_APP_ID = "V8H6LQ9448.io.uebelacker.AppAttestExample";

async function loadFixture(name: "development" | "production") {
  const json = JSON.parse(
    await Deno.readTextFile(new URL(`./testdata/attestation-${name}.json`, import.meta.url)),
  );
  const attestation = fromBase64(json.attestation);
  const decoded = decodeCbor(attestation);
  // Verify "as of" a moment inside the leaf certificate's validity window —
  // these leaves live for days and expired long ago.
  const leaf = new x509.X509Certificate(decoded.attStmt.x5c[0]);
  const now = new Date(leaf.notBefore.getTime() + 60_000);
  return {
    attestation,
    decoded,
    challenge: fromBase64(json.challenge),
    keyId: json.keyId as string,
    now,
  };
}

for (const environment of ["development", "production"] as const) {
  Deno.test(`real ${environment} attestation verifies`, async () => {
    const f = await loadFixture(environment);
    const result = await verifyAttestation({
      attestation: f.attestation,
      challenge: f.challenge,
      keyId: f.keyId,
      appId: FIXTURE_APP_ID,
      now: f.now,
    });
    assertEquals(result.environment, environment);
    assertEquals(result.publicKeySpki.length, 91);
    assertEquals(toBase64(await sha256(result.publicKeySpki.slice(-65))), f.keyId);
  });
}

Deno.test("attestation for another app is rejected", async () => {
  const f = await loadFixture("production");
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: f.attestation,
        challenge: f.challenge,
        keyId: f.keyId,
        appId: "9HP4Y79QFR.com.thehumaninternet.app",
        now: f.now,
      }),
    AppAttestError,
    "different app",
  );
});

Deno.test("attestation with a different challenge is rejected", async () => {
  const f = await loadFixture("production");
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: f.attestation,
        challenge: new TextEncoder().encode("not the challenge we issued"),
        keyId: f.keyId,
        appId: FIXTURE_APP_ID,
        now: f.now,
      }),
    AppAttestError,
    "nonce",
  );
});

Deno.test("attestation claimed for a different key id is rejected", async () => {
  const f = await loadFixture("production");
  const other = await loadFixture("development");
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: f.attestation,
        challenge: f.challenge,
        keyId: other.keyId,
        appId: FIXTURE_APP_ID,
        now: f.now,
      }),
    AppAttestError,
    "key id",
  );
});

Deno.test("attestation outside its certificates' validity is rejected", async () => {
  const f = await loadFixture("production");
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: f.attestation,
        challenge: f.challenge,
        keyId: f.keyId,
        appId: FIXTURE_APP_ID,
        now: new Date("2026-09-25T00:00:00Z"),
      }),
    AppAttestError,
    "certificate chain",
  );
});

Deno.test("attestation not chaining to the pinned root is rejected", async () => {
  const f = await loadFixture("production");
  // Any other self-signed CA stands in for "a root that isn't Apple's".
  const alg = { name: "ECDSA", namedCurve: "P-384", hash: "SHA-384" };
  const keys = await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
  const impostor = await x509.X509CertificateGenerator.createSelfSigned({
    name: "CN=Apple App Attestation Root CA",
    notBefore: new Date("2020-01-01"),
    notAfter: new Date("2045-01-01"),
    signingAlgorithm: alg,
    keys,
  });
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: f.attestation,
        challenge: f.challenge,
        keyId: f.keyId,
        appId: FIXTURE_APP_ID,
        now: f.now,
        rootCertPem: impostor.toString("pem"),
      }),
    AppAttestError,
    "certificate chain",
  );
});

Deno.test("attestation with tampered authData is rejected", async () => {
  const f = await loadFixture("production");
  const authData = new Uint8Array(f.decoded.authData);
  authData[40] ^= 0xff; // inside the AAGUID
  const tampered = encodeCbor({ ...f.decoded, authData });
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: tampered,
        challenge: f.challenge,
        keyId: f.keyId,
        appId: FIXTURE_APP_ID,
        now: f.now,
      }),
    AppAttestError,
    "nonce",
  );
});

Deno.test("attestation that isn't CBOR is rejected", async () => {
  await assertRejects(
    () =>
      verifyAttestation({
        attestation: new TextEncoder().encode("{\"fmt\":\"apple-appattest\"}"),
        challenge: new Uint8Array(1),
        keyId: "AAAA",
      }),
    AppAttestError,
  );
});

// ---- assertions -------------------------------------------------------------

Deno.test("real assertion from Apple's service verifies", async () => {
  const assertion = fromBase64(
    "omlzaWduYXR1cmVYRzBFAiBB8BGAwkmFCg1M5J0mOYEun0SUN1/lse79/7ypG9WiMQIhAIHvqj7eg59B1PMFX1CN4GMGlsgfFtdL30pHCf7G/dNRcWF1dGhlbnRpY2F0b3JEYXRhWCXKPdw7T3iujcFZbHVrHX0mDSMrNms5PzEbrFbQPRA6rEAAAAAB",
  );
  const publicKeySpki = fromBase64(
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEg69t2YzgcPTLUx8Zgu+rbcikeaEL8Ppb+HG0QTIulz8YUB9tgv1pDRruWk87nZC3our56pzIWaqXEbaWyamdzA==",
  );
  const clientData = new TextEncoder().encode(
    '{"subject":"Lorem ipsum","message":"Lorem ipsum dolor sit amet, consectetur adipiscing elit."}',
  );
  const { signCount } = await verifyAssertion({
    assertion,
    clientData,
    publicKeySpki,
    appId: FIXTURE_APP_ID,
  });
  assertEquals(signCount, 1);

  await assertRejects(
    () =>
      verifyAssertion({
        assertion,
        clientData: concat(clientData, new Uint8Array([0])),
        publicKeySpki,
        appId: FIXTURE_APP_ID,
      }),
    AppAttestError,
    "signature is invalid",
  );
});

/// Builds an assertion the way the Secure Enclave does: DER ECDSA over
/// SHA256(SHA256(authenticatorData ‖ SHA256(clientData))).
async function makeAssertion(opts: {
  privateKey: CryptoKey;
  clientData: Uint8Array;
  appId: string;
  signCount: number;
}) {
  const rpIdHash = await sha256(new TextEncoder().encode(opts.appId));
  const counter = new Uint8Array(4);
  new DataView(counter.buffer).setUint32(0, opts.signCount);
  const authenticatorData = concat(rpIdHash, new Uint8Array([0x40]), counter);
  const nonce = await sha256(concat(authenticatorData, await sha256(opts.clientData)));
  const raw = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, opts.privateKey, nonce.slice().buffer as ArrayBuffer),
  );
  return encodeCbor({ signature: rawToDer(raw), authenticatorData });
}

function rawToDer(raw: Uint8Array): Uint8Array {
  const integer = (bytes: Uint8Array) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let out: Uint8Array = bytes.slice(i);
    if (out[0] & 0x80) out = concat(new Uint8Array([0]), out);
    return concat(new Uint8Array([0x02, out.length]), out);
  };
  const body = concat(integer(raw.slice(0, 32)), integer(raw.slice(32)));
  return concat(new Uint8Array([0x30, body.length]), body);
}

async function newKey() {
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey));
  return { privateKey: pair.privateKey, spki };
}

const OUR_APP_ID = "9HP4Y79QFR.com.thehumaninternet.app";

Deno.test("assertion over a photo verifies, and binds to exactly those bytes", async () => {
  const { privateKey, spki } = await newKey();
  const photo = crypto.getRandomValues(new Uint8Array(4096));
  const assertion = await makeAssertion({ privateKey, clientData: photo, appId: OUR_APP_ID, signCount: 7 });

  const { signCount } = await verifyAssertion({ assertion, clientData: photo, publicKeySpki: spki });
  assertEquals(signCount, 7);

  const swapped = photo.slice();
  swapped[100] ^= 1;
  await assertRejects(
    () => verifyAssertion({ assertion, clientData: swapped, publicKeySpki: spki }),
    AppAttestError,
    "signature is invalid",
  );
});

Deno.test("assertion from a different key is rejected", async () => {
  const signer = await newKey();
  const registered = await newKey();
  const photo = new Uint8Array([1, 2, 3]);
  const assertion = await makeAssertion({
    privateKey: signer.privateKey,
    clientData: photo,
    appId: OUR_APP_ID,
    signCount: 1,
  });
  await assertRejects(
    () => verifyAssertion({ assertion, clientData: photo, publicKeySpki: registered.spki }),
    AppAttestError,
    "signature is invalid",
  );
});

Deno.test("assertion for another app id is rejected", async () => {
  const { privateKey, spki } = await newKey();
  const photo = new Uint8Array([1, 2, 3]);
  const assertion = await makeAssertion({
    privateKey,
    clientData: photo,
    appId: "ABCDE12345.com.someone.else",
    signCount: 1,
  });
  await assertRejects(
    () => verifyAssertion({ assertion, clientData: photo, publicKeySpki: spki }),
    AppAttestError,
    "different app",
  );
});

Deno.test("assertion with a zero counter is rejected", async () => {
  const { privateKey, spki } = await newKey();
  const photo = new Uint8Array([1, 2, 3]);
  const assertion = await makeAssertion({ privateKey, clientData: photo, appId: OUR_APP_ID, signCount: 0 });
  await assertRejects(
    () => verifyAssertion({ assertion, clientData: photo, publicKeySpki: spki }),
    AppAttestError,
    "counter",
  );
});

Deno.test("garbage assertion is rejected as an AppAttestError", async () => {
  const { spki } = await newKey();
  await assertRejects(
    () =>
      verifyAssertion({
        assertion: encodeCbor({ signature: new Uint8Array([1, 2]), authenticatorData: new Uint8Array(37) }),
        clientData: new Uint8Array([1]),
        publicKeySpki: spki,
      }),
    AppAttestError,
  );
});

Deno.test("DER → raw signature handles padded and short integers", () => {
  const r = new Uint8Array(32).fill(0x80); // high bit set ⇒ DER pads with 00
  const s = concat(new Uint8Array(2), new Uint8Array(30).fill(0x11)); // leading zeros ⇒ DER shortens
  const raw = derToRawEcdsaSignature(rawToDer(concat(r, s)), 32);
  assert(raw.length === 64);
  assertEquals(raw.slice(0, 32), r);
  assertEquals(raw.slice(32), s);
});
