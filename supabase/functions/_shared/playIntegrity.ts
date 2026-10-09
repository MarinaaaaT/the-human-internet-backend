// Verification of Google Play Integrity tokens — the Android counterpart of
// `appAttest.ts`: the check that a request came from a genuine build of the
// Android app, installed from Google Play, on a genuine Android device.
// Used by `sign-photo`, one token per photo signed.
//
// Unlike App Attest there is nothing to verify locally and no per-install key
// to register. A token is opaque to us: Google encrypts it, and only Google's
// `decodeIntegrityToken` endpoint — called here with this project's service
// account — turns it into a verdict. So this file has two halves:
//   - `decodeIntegrityToken`, the network call to Google;
//   - `evaluateVerdict`, a pure function over what came back, which is where
//     every decision this endpoint's trust rests on is spelled out.
//
// What binds a token to a photo is its **request hash**: the app asks Google
// for a token over SHA-256 of the exact bytes it is about to send, and
// `evaluateVerdict` requires that hash to match the body that arrived. A
// token lifted from one request is useless for signing different bytes.
//
// What this does and doesn't prove is the same as App Attest: the request
// came from our app, as Google Play distributes it, on a device that passes
// Android's integrity checks. It does **not** prove the bytes came off the
// camera — a rooted device that still passes can hook the capture path.

/// The Android app's package name (its `applicationId`), as registered in
/// Google Play. Mirrors `APP_ID` in `appAttest.ts`.
export const ANDROID_PACKAGE_NAME = "com.thehumaninternet.app";

/// How old a token may be. The app requests one immediately before each
/// signing attempt, so anything older than this was not made for the request
/// it arrived on.
const MAX_TOKEN_AGE_MS = 10 * 60 * 1000;
/// Tolerance for the device's or Google's clock running ahead of ours.
const MAX_CLOCK_SKEW_MS = 2 * 60 * 1000;

const TOKEN_URI = "https://oauth2.googleapis.com/token";
const SCOPE = "https://www.googleapis.com/auth/playintegrity";

/// A token that decoded but doesn't meet the bar, or that Google refused to
/// decode at all. Anything else thrown from here (network failure, Google
/// 5xx) is an outage, not a verdict, and must not be reported as one.
export class PlayIntegrityError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PlayIntegrityError";
  }
}

/// The two fields of a Google service account key this needs.
export interface ServiceAccount {
  client_email: string;
  private_key: string;
}

/// The request hash the Android app must have asked Google to bind the token
/// to: SHA-256 of the request body, base64url without padding. Mirrored by
/// `PlayIntegrityService.requestHash` in the Android app — the two must
/// produce the same string for the same bytes.
export async function expectedRequestHash(body: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", body as BufferSource));
  return toBase64Url(digest);
}

/// Decides whether a decoded token (`tokenPayloadExternal` from Google) is
/// good enough to sign for. Throws `PlayIntegrityError` naming the first
/// check that failed; returns normally otherwise.
///
/// The first three checks tie the token to *this request*; the last two are
/// about *what* made it. A debug build installed over USB, or anything
/// running in the emulator, is by definition not the build Google Play
/// distributes and fails them — for everyone, admins included. Android is
/// tested on a real phone with a build from a Play testing track.
export function evaluateVerdict(
  payload: unknown,
  params: {
    expectedRequestHash: string;
    now?: number;
  },
): void {
  const root = asRecord(payload, "token payload");
  const request = asRecord(root.requestDetails, "requestDetails");

  // 1. Made by our app's package. Google fills this in from the app that
  //    asked for the token, not from anything the caller sends.
  if (request.requestPackageName !== ANDROID_PACKAGE_NAME) {
    throw new PlayIntegrityError("token was requested by a different package");
  }

  // 2. Made over exactly the bytes that arrived.
  if (typeof request.requestHash !== "string" || request.requestHash !== params.expectedRequestHash) {
    throw new PlayIntegrityError("request hash does not match the request body");
  }

  // 3. Made just now.
  const issuedAt = Number(request.timestampMillis);
  const now = params.now ?? Date.now();
  if (!Number.isFinite(issuedAt)) {
    throw new PlayIntegrityError("token has no timestamp");
  }
  if (now - issuedAt > MAX_TOKEN_AGE_MS) {
    throw new PlayIntegrityError("token is too old");
  }
  if (issuedAt - now > MAX_CLOCK_SKEW_MS) {
    throw new PlayIntegrityError("token is dated in the future");
  }

  // 4. The binary is the one Google Play distributes: same package, same
  //    signing certificate, a version Play knows. `UNRECOGNIZED_VERSION` is a
  //    sideloaded or modified build; `UNEVALUATED` means Google couldn't tell.
  const app = asRecord(root.appIntegrity, "appIntegrity");
  if (app.appRecognitionVerdict !== "PLAY_RECOGNIZED") {
    throw new PlayIntegrityError(`app is not Play-recognized (${String(app.appRecognitionVerdict)})`);
  }

  // 5. The device is a genuine, certified Android device — not an emulator,
  //    and not one with a compromised system image.
  const device = asRecord(root.deviceIntegrity, "deviceIntegrity");
  const verdicts = Array.isArray(device.deviceRecognitionVerdict) ? device.deviceRecognitionVerdict : [];
  if (!verdicts.includes("MEETS_DEVICE_INTEGRITY")) {
    throw new PlayIntegrityError("device does not meet device integrity");
  }
}

/// Asks Google to decrypt and verify a token, returning its
/// `tokenPayloadExternal`. A token Google rejects outright (malformed,
/// expired, issued for another project) is a `PlayIntegrityError`; any other
/// failure is thrown as-is, so the caller can tell "bad token" from "couldn't
/// reach Google".
export async function decodeIntegrityToken(
  token: string,
  serviceAccount: ServiceAccount,
): Promise<unknown> {
  const response = await fetch(
    `https://playintegrity.googleapis.com/v1/${ANDROID_PACKAGE_NAME}:decodeIntegrityToken`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${await accessToken(serviceAccount)}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ integrity_token: token }),
    },
  );
  if (response.status === 400) {
    throw new PlayIntegrityError("Google could not decode the token");
  }
  if (!response.ok) {
    throw new Error(`decodeIntegrityToken failed: ${response.status} ${await response.text()}`);
  }
  const decoded = asRecord(await response.json(), "decode response");
  return decoded.tokenPayloadExternal;
}

/// Reads the service account from the `PLAY_INTEGRITY_SERVICE_ACCOUNT` secret
/// — the whole JSON key file Google Cloud hands out — or `null` when it isn't
/// set, so the function can run (and iOS can keep signing) before the Android
/// side is configured.
export function loadServiceAccount(): ServiceAccount | null {
  const raw = Deno.env.get("PLAY_INTEGRITY_SERVICE_ACCOUNT");
  if (!raw) return null;
  const parsed = JSON.parse(raw);
  if (typeof parsed?.client_email !== "string" || typeof parsed?.private_key !== "string") {
    throw new Error("PLAY_INTEGRITY_SERVICE_ACCOUNT is not a service account key");
  }
  return { client_email: parsed.client_email, private_key: parsed.private_key };
}

let cachedAccessToken: { value: string; expiresAt: number } | null = null;

/// An OAuth access token for the service account, via Google's JWT-bearer
/// grant. Cached for its lifetime: an Edge Function instance serves many
/// requests, and each would otherwise cost an extra round trip to Google.
async function accessToken(serviceAccount: ServiceAccount): Promise<string> {
  if (cachedAccessToken && cachedAccessToken.expiresAt > Date.now() + 60_000) {
    return cachedAccessToken.value;
  }

  const issuedAt = Math.floor(Date.now() / 1000);
  const assertion = await signJwt(
    { iss: serviceAccount.client_email, scope: SCOPE, aud: TOKEN_URI, iat: issuedAt, exp: issuedAt + 3600 },
    serviceAccount.private_key,
  );
  const response = await fetch(TOKEN_URI, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion,
    }),
  });
  if (!response.ok) {
    throw new Error(`Google token exchange failed: ${response.status} ${await response.text()}`);
  }
  const body = await response.json();
  cachedAccessToken = { value: body.access_token, expiresAt: Date.now() + body.expires_in * 1000 };
  return cachedAccessToken.value;
}

/// RS256, the only algorithm Google accepts for this grant.
async function signJwt(claims: Record<string, unknown>, privateKeyPem: string): Promise<string> {
  const encoder = new TextEncoder();
  const header = toBase64Url(encoder.encode(JSON.stringify({ alg: "RS256", typ: "JWT" })));
  const payload = toBase64Url(encoder.encode(JSON.stringify(claims)));
  const signingInput = `${header}.${payload}`;

  const der = Uint8Array.from(
    atob(privateKeyPem.replace(/-----[A-Z ]+-----/g, "").replace(/\s+/g, "")),
    (c) => c.charCodeAt(0),
  );
  const key = await crypto.subtle.importKey(
    "pkcs8",
    der,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, encoder.encode(signingInput)),
  );
  return `${signingInput}.${toBase64Url(signature)}`;
}

function asRecord(value: unknown, name: string): Record<string, unknown> {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  throw new PlayIntegrityError(`${name} is missing`);
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
