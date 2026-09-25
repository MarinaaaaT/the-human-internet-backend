// Verification of Apple App Attest objects — the check that a request came
// from a genuine, unmodified build of the iOS app on a genuine Apple device.
// Shared by `app-attest-register` (one attestation per app install) and
// `sign-photo` (one assertion per photo signed).
//
// Implements Apple's "Validating apps that connect to your server" steps
// directly rather than through a library: the two small npm libraries that
// do this are Node-only (`crypto.createVerify`, Node X.509), and this is the
// one check the signing endpoint's trust rests on, so every step is spelled
// out here where it can be read against Apple's list.
//
// What this does and doesn't prove is the same as App Attest's own promise:
// the request came from our app, signed by our team, on real Apple hardware
// whose key never left the Secure Enclave. It does **not** prove the bytes
// came off the camera — a jailbroken device can still hook the capture path.
// It raises the bar from "anyone with a session token and curl" to "jailbreak
// and hook the app", which is the realistic ceiling for this whole category.

import { decode as decodeCbor } from "npm:cbor-x@1";
import * as x509 from "npm:@peculiar/x509@1";

/// Apple App Attestation Root CA — pinned, never fetched. SHA-256 fingerprint
/// 1C:B9:82:3B:A2:8B:A6:AD:2D:33:A0:06:94:1D:E2:AE:4F:51:3E:F1:D4:E8:31:B9:F7:E0:FA:7B:62:42:C9:32,
/// published at https://www.apple.com/certificateauthority/private/.
/// Valid until 2045.
export const APPLE_APP_ATTEST_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`;

/// `<Team ID>.<bundle ID>` of the iOS app — what Apple hashes into every
/// attestation and assertion as the relying-party id. Mirrors
/// `DEVELOPMENT_TEAM` and `PRODUCT_BUNDLE_IDENTIFIER` in the app's
/// `.pbxproj`; if either ever changes, every existing key stops verifying.
export const APP_ID = "9HP4Y79QFR.com.thehumaninternet.app";

/// Which App Attest environment a key was minted in. Development keys come
/// only from development-signed builds (Xcode runs); distributed builds get
/// production ones. Both are bound to our team and bundle id by `APP_ID`, so
/// a development key still can't come from anyone else's build.
export type AppAttestEnvironment = "production" | "development";

const AAGUID_PRODUCTION = concat(
  new TextEncoder().encode("appattest"),
  new Uint8Array(7),
);
const AAGUID_DEVELOPMENT = new TextEncoder().encode("appattestdevelop");

/// OID of the credential certificate extension carrying the attestation nonce.
const NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

export class AppAttestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AppAttestError";
  }
}

export interface VerifiedAttestation {
  /// The attested key's public half, SPKI DER. Stored per key id and used to
  /// check every later assertion.
  publicKeySpki: Uint8Array;
  environment: AppAttestEnvironment;
}

/// Validates a one-time attestation object for `keyId`, per Apple's nine
/// steps. `challenge` is the exact bytes the server issued and the app hashed
/// as its clientData; the caller is responsible for it being one it issued,
/// to this user, recently, and never before.
export async function verifyAttestation(params: {
  attestation: Uint8Array;
  challenge: Uint8Array;
  keyId: string; // base64, as DCAppAttestService hands it out
  appId?: string;
  rootCertPem?: string;
  now?: Date;
}): Promise<VerifiedAttestation> {
  const appId = params.appId ?? APP_ID;
  const now = params.now ?? new Date();
  const keyIdBytes = fromBase64(params.keyId);

  let decoded: {
    fmt?: unknown;
    attStmt?: { x5c?: unknown; receipt?: unknown };
    authData?: unknown;
  };
  try {
    decoded = decodeCbor(params.attestation);
  } catch {
    throw new AppAttestError("attestation is not valid CBOR");
  }
  if (decoded?.fmt !== "apple-appattest") {
    throw new AppAttestError("unexpected attestation format");
  }
  const x5c = decoded.attStmt?.x5c;
  if (!Array.isArray(x5c) || x5c.length < 2) {
    throw new AppAttestError("attestation is missing its certificate chain");
  }
  const authData = asBytes(decoded.authData, "authData");

  // 1. The credential certificate chains to Apple's App Attest root, through
  //    the intermediate the attestation carries, and all three are in date.
  const credCert = new x509.X509Certificate(buf(asBytes(x5c[0], "x5c[0]")));
  const intermediate = new x509.X509Certificate(buf(asBytes(x5c[1], "x5c[1]")));
  const root = new x509.X509Certificate(params.rootCertPem ?? APPLE_APP_ATTEST_ROOT_CA_PEM);
  const chainOK =
    (await credCert.verify({ publicKey: intermediate.publicKey, date: now })) &&
    (await intermediate.verify({ publicKey: root.publicKey, date: now })) &&
    (await root.verify({ date: now }));
  if (!chainOK) {
    throw new AppAttestError("certificate chain does not verify to Apple's App Attest root");
  }

  // 2–4. nonce = SHA256(authData ‖ SHA256(clientData)), and it must be the
  //      one Apple embedded in the credential certificate.
  const clientDataHash = await sha256(params.challenge);
  const nonce = await sha256(concat(authData, clientDataHash));
  const extension = credCert.getExtension(NONCE_EXTENSION_OID);
  if (!extension) throw new AppAttestError("credential certificate has no nonce extension");
  const embeddedNonce = nonceFromExtension(new Uint8Array(extension.value));
  if (!equal(embeddedNonce, nonce)) {
    throw new AppAttestError("nonce does not match the challenge");
  }

  // 5. The key id is the SHA-256 of the credential's public key (the raw
  //    uncompressed EC point, i.e. the SPKI's BIT STRING contents).
  const publicKeySpki = new Uint8Array(credCert.publicKey.rawData);
  const publicKeyPoint = publicKeySpki.slice(publicKeySpki.length - 65);
  if (publicKeyPoint[0] !== 0x04 || !equal(await sha256(publicKeyPoint), keyIdBytes)) {
    throw new AppAttestError("key id does not match the attested public key");
  }

  // 6–9. Authenticator data: our app id, a zero counter, an App Attest
  //      AAGUID, and a credential id equal to the key id.
  const parsed = parseAuthenticatorData(authData);
  if (!equal(parsed.rpIdHash, await sha256(new TextEncoder().encode(appId)))) {
    throw new AppAttestError("attestation is for a different app");
  }
  if (parsed.signCount !== 0) {
    throw new AppAttestError("attestation counter is not zero");
  }
  if (authData.length < 55) throw new AppAttestError("authData is too short");
  const aaguid = authData.slice(37, 53);
  const environment: AppAttestEnvironment | null = equal(aaguid, AAGUID_PRODUCTION)
    ? "production"
    : equal(aaguid, AAGUID_DEVELOPMENT)
    ? "development"
    : null;
  if (!environment) throw new AppAttestError("unrecognised App Attest environment");
  const credentialIdLength = (authData[53] << 8) | authData[54];
  const credentialId = authData.slice(55, 55 + credentialIdLength);
  if (!equal(credentialId, keyIdBytes)) {
    throw new AppAttestError("credential id does not match the key id");
  }

  return { publicKeySpki, environment };
}

/// Validates a per-request assertion: `clientData` is the exact bytes the
/// app passed (hashed) to `generateAssertion`, and the signature must come
/// from the key registered under that key id. Returns the assertion's
/// counter, which the caller persists.
///
/// The counter is deliberately *not* required to exceed the stored one.
/// `sign-photo`'s clientData is the image itself, so a replayed assertion can
/// only get the very same bytes signed again — nothing its holder didn't
/// already have — while the app signs two photos concurrently and their
/// requests can legitimately arrive out of counter order. Requiring strict
/// order there would fail real uploads to prevent a replay that gains nothing.
export async function verifyAssertion(params: {
  assertion: Uint8Array;
  clientData: Uint8Array;
  publicKeySpki: Uint8Array;
  appId?: string;
}): Promise<{ signCount: number }> {
  const appId = params.appId ?? APP_ID;

  let decoded: { signature?: unknown; authenticatorData?: unknown };
  try {
    decoded = decodeCbor(params.assertion);
  } catch {
    throw new AppAttestError("assertion is not valid CBOR");
  }
  const signature = asBytes(decoded?.signature, "signature");
  const authenticatorData = asBytes(decoded?.authenticatorData, "authenticatorData");

  // 1–3. nonce = SHA256(authenticatorData ‖ SHA256(clientData)), signed
  //      (ECDSA P-256 / SHA-256, DER-encoded) by the attested key.
  const clientDataHash = await sha256(params.clientData);
  const nonce = await sha256(concat(authenticatorData, clientDataHash));
  const key = await crypto.subtle.importKey(
    "spki",
    buf(params.publicKeySpki),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  let rawSignature: Uint8Array;
  try {
    rawSignature = derToRawEcdsaSignature(signature, 32);
  } catch {
    throw new AppAttestError("assertion signature is malformed");
  }
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    buf(rawSignature),
    buf(nonce),
  );
  if (!valid) throw new AppAttestError("assertion signature is invalid");

  // 4. Our app id.
  const parsed = parseAuthenticatorData(authenticatorData);
  if (!equal(parsed.rpIdHash, await sha256(new TextEncoder().encode(appId)))) {
    throw new AppAttestError("assertion is for a different app");
  }
  // 5. Apple's counter starts at 1 for the first assertion; 0 only ever
  //    appears in the attestation itself.
  if (parsed.signCount < 1) throw new AppAttestError("assertion counter is not positive");

  return { signCount: parsed.signCount };
}

// ---- helpers ---------------------------------------------------------------

function parseAuthenticatorData(authData: Uint8Array) {
  if (authData.length < 37) throw new AppAttestError("authenticator data is too short");
  const view = new DataView(authData.buffer, authData.byteOffset, authData.byteLength);
  return {
    rpIdHash: authData.slice(0, 32),
    signCount: view.getUint32(33),
  };
}

/// The nonce extension is `SEQUENCE { [1] EXPLICIT OCTET STRING (32) }`.
/// Checked byte-for-byte rather than with a general DER parser: there's
/// exactly one shape Apple emits, and anything else should fail.
function nonceFromExtension(value: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([0x30, 0x24, 0xa1, 0x22, 0x04, 0x20]);
  if (value.length !== prefix.length + 32 || !equal(value.slice(0, prefix.length), prefix)) {
    throw new AppAttestError("nonce extension has an unexpected shape");
  }
  return value.slice(prefix.length);
}

/// WebCrypto verifies ECDSA signatures in IEEE P1363 form (r ‖ s, fixed
/// width); App Attest hands out ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
export function derToRawEcdsaSignature(der: Uint8Array, size: number): Uint8Array {
  let offset = 0;
  if (der[offset++] !== 0x30) throw new Error("not a SEQUENCE");
  let seqLength = der[offset++];
  if (seqLength & 0x80) {
    const bytes = seqLength & 0x7f;
    seqLength = 0;
    for (let i = 0; i < bytes; i++) seqLength = (seqLength << 8) | der[offset++];
  }
  if (offset + seqLength !== der.length) throw new Error("bad SEQUENCE length");
  const out = new Uint8Array(size * 2);
  for (let part = 0; part < 2; part++) {
    if (der[offset++] !== 0x02) throw new Error("not an INTEGER");
    const length = der[offset++];
    let integer = der.slice(offset, offset + length);
    offset += length;
    while (integer.length > size && integer[0] === 0) integer = integer.slice(1);
    if (integer.length > size) throw new Error("INTEGER too long");
    out.set(integer, part * size + (size - integer.length));
  }
  if (offset !== der.length) throw new Error("trailing bytes");
  return out;
}

/// A standalone ArrayBuffer copy of `bytes`, for APIs (WebCrypto, X.509)
/// typed to reject views over a possibly-shared buffer.
function buf(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

function asBytes(value: unknown, name: string): Uint8Array {
  if (value instanceof Uint8Array) return new Uint8Array(value);
  throw new AppAttestError(`${name} is missing or not a byte string`);
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf(data)));
}

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function fromBase64(value: string): Uint8Array {
  try {
    return Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  } catch {
    throw new AppAttestError("value is not valid base64");
  }
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}
