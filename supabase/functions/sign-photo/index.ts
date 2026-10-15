// Forwards a raw captured JPEG to the AWS Lambda that holds the real C2PA
// signing key (in AWS KMS — never in this function, never in the app) and
// returns the signed JPEG bytes. `RemotePhotoSigner` (iOS and Android) calls
// this for every photo the apps upload.
//
// Runs with the caller's own JWT forwarded by `supabase.functions.invoke`,
// so this only ever signs a photo on behalf of the authenticated user
// calling it — same auth pattern as stripe-identity-session. The AWS
// credentials below are this function's own, SigV4-scoped to
// `lambda:InvokeFunctionUrl` on exactly the one signing Lambda, nothing
// else in the AWS account.
//
// **App Attest.** A session token alone used to be enough to get *any* bytes
// signed as a `digitalCapture` — including an AI image sent with curl. So a
// request may now carry an App Attest assertion over the exact body
// (`X-App-Attest-Key-Id` + `X-App-Attest-Assertion`, base64), made by a key
// `app-attest-register` verified came from our app on real Apple hardware:
//   - assertion present ⇒ it must verify, or nothing is signed;
//   - assertion absent  ⇒ refused if the `require_app_attest` flag resolves
//     on for this caller, otherwise signed and logged. The flag starts `off`
//     because every build already in the wild sends no assertion.
// Errors carry a `code` the app acts on: `attestation_key_unknown` and
// `attestation_invalid` make it discard its key and register a fresh one.
//
// **Play Integrity** is the same gate for Android, which has no App Attest:
// a request may carry `X-Play-Integrity-Token`, a Google Play Integrity token
// the app requested over SHA-256 of the exact body. It counts as attested
// when Google decodes it to a Play-installed build of our app on a genuine
// device (`_shared/playIntegrity.ts`). The one flag governs both platforms —
// see `checkPlayIntegrity` for how its failure handling differs from App
// Attest's, and why.
//
// **Capture pipeline** (`X-Capture-Pipeline: server-watermark-v1` +
// `X-Photo-Id`): the body is the *raw* capture. One Lambda call (`/pipeline`)
// signs it as a capture (the original), burns the brand mark into that signed
// capture and signs the result with it as the parent ingredient (the photo).
// The original is copied into the private `photo-originals` bucket inside
// Storage, and the photo is returned for the app to upload. A Lambda deployed
// before `/pipeline` answers it 404, and then the same work is done in two
// calls, `/capture` then `/watermark`. Without the header the body is signed
// as-is — the legacy path every build predating this still uses, sending
// bytes it watermarked itself.
//
// **Storage hand-off.** Photos reach the Lambda as short-lived signed links,
// not request bodies: a Function URL caps each request and response at 6MB
// after base64 (~4.5MB of JPEG), and a detailed capture is bigger — it was
// refused with a 413 before reaching the Lambda, on every retry. Each call
// puts the input in the private `signing-handoff` bucket, sends the Lambda a
// download link for it and an upload link for each output, then fetches the
// output it returns, checks its SHA-256, and deletes them all once the
// response has gone. See `invokeLambda`, `invokePipeline`, and
// aws-signing-lambda/src/handoff.rs. Requires the bucket
// (supabase/sql/2026-10-10_signing_handoff.sql) and a Lambda that has
// HANDOFF_STORAGE_HOST set.
//
// Required secrets (`supabase secrets set`): SIGNING_LAMBDA_URL,
// AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY. Until those are
// set this function 500s. Optional: PLAY_INTEGRITY_SERVICE_ACCOUNT (a Google
// service account key, JSON) — without it no Android request can be attested.

import { createClient } from "npm:@supabase/supabase-js@2";
import { SignatureV4 } from "npm:@aws-sdk/signature-v4@3";
import { HttpRequest } from "npm:@aws-sdk/protocol-http@3";
import { Sha256 } from "npm:@aws-crypto/sha256-js@5";
import { AppAttestError, fromBase64, verifyAssertion } from "../_shared/appAttest.ts";
import {
  decodeIntegrityToken,
  evaluateVerdict,
  expectedRequestHash,
  loadServiceAccount,
  PlayIntegrityError,
} from "../_shared/playIntegrity.ts";

const LAMBDA_FUNCTION_URL = Deno.env.get("SIGNING_LAMBDA_URL")!;
const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const AWS_REGION = Deno.env.get("AWS_REGION")!;

/// Mirrors FeatureFlagAudience.includes(isAdmin:). A missing row or an
/// audience this function doesn't recognise reads as off — the rollout
/// default, since failing closed on a flag we couldn't read would stop every
/// upload from every build that predates attestation.
const REQUIRE_APP_ATTEST_FLAG = "require_app_attest";

/// Carries the Android app's Play Integrity token. Mirrored in the Android
/// app's `PlayIntegrityService`.
const PLAY_INTEGRITY_HEADER = "X-Play-Integrity-Token";

/// Opts a request into the capture pipeline, and is echoed on the response
/// so the app can tell a backend that did the watermarking from one that
/// predates it (and would have signed the raw capture as-is — which the app
/// must never upload as the shared photo).
const PIPELINE_HEADER = "X-Capture-Pipeline";
const CAPTURE_PIPELINE = "server-watermark-v1";

/// Private bucket holding each signed capture — the ingredient of the photo
/// that's shared. Owner-readable, written only here with the service role.
const ORIGINALS_BUCKET = "photo-originals";

/// Private, policy-less bucket the photos pass through on their way to and
/// from the Lambda — see "Storage hand-off" above.
const HANDOFF_BUCKET = "signing-handoff";

/// How long the Lambda's links stay valid. Each is used within seconds of
/// being made; the margin only covers a cold start, and a retry gets new ones.
const HANDOFF_LINK_SECONDS = 300;

/// Selects the Lambda's storage transport, and is echoed back by a Lambda
/// that used it. Mirrored in aws-signing-lambda/src/handoff.rs.
const TRANSPORT_HEADER = "x-signing-transport";
const STORAGE_TRANSPORT = "storage-v1";

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

const signer = new SignatureV4({
  service: "lambda",
  region: AWS_REGION,
  credentials: {
    accessKeyId: Deno.env.get("AWS_ACCESS_KEY_ID")!,
    secretAccessKey: Deno.env.get("AWS_SECRET_ACCESS_KEY")!,
  },
  sha256: Sha256,
});

Deno.serve(async (req) => {
  try {
    const supabaseClient = createClient(
      SUPABASE_URL,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } },
    );

    const {
      data: { user },
      error: userError,
    } = await supabaseClient.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Not authenticated" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const body = await req.arrayBuffer();
    const imageData = new Uint8Array(body);
    if (imageData.length === 0) {
      return new Response(JSON.stringify({ error: "Missing image data" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const refusal = await checkAppAttest(req, imageData, user.id, supabaseClient);
    if (refusal) return refusal;

    const photoID = req.headers.get("X-Photo-Id")?.toLowerCase();
    if (req.headers.get(PIPELINE_HEADER) === CAPTURE_PIPELINE) {
      if (!photoID || !UUID_PATTERN.test(photoID)) {
        return new Response(JSON.stringify({ error: "X-Photo-Id must be the photo's UUID" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        });
      }
      return await signCapturePipeline(body, user.id, photoID);
    }

    // Legacy: sign the body as-is. What every build predating server-side
    // watermarking sends — already-watermarked bytes.
    const signed = await invokeLambda("capture", body);
    if (!signed) return signingFailed();
    return new Response(signed, { headers: { "Content-Type": "image/jpeg" } });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: "Couldn't sign photo" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});

/// The capture pipeline: the body is the raw capture.
///   1. sign it as-is — `c2pa.created` / `digitalCapture` (the original);
///   2. burn the brand mark into *that signed capture* and sign the result
///      with it as the parent ingredient (the photo);
///   3. keep the original in the originals bucket, for photo history;
///   4. hand back the photo, which the app uploads as the photo.
/// One Lambda call does 1 and 2 (`/pipeline`); a Lambda deployed before that
/// route answers it 404, and then they're done in two (`/capture`,
/// `/watermark`), as before it existed.
/// The App Attest assertion (checked before this) is over the raw capture,
/// so the chain starts at bytes the app itself captured.
async function signCapturePipeline(
  rawCapture: ArrayBuffer,
  userID: string,
  photoID: string,
): Promise<Response> {
  // Same `{user_id}/{photo_id}.jpg` shape as the photos bucket. Overwritten,
  // so a retry after a later step failed just replaces the same object.
  const originalPath = `${userID}/${photoID}.jpg`;

  let watermarked = await invokePipeline(rawCapture, originalPath);
  if (watermarked === NO_PIPELINE_ROUTE) {
    console.warn("Signing Lambda has no /pipeline route yet; signing in two calls");
    watermarked = await signInTwoCalls(rawCapture, originalPath);
  }
  if (!watermarked) return signingFailed();

  return new Response(watermarked, {
    headers: { "Content-Type": "image/jpeg", [PIPELINE_HEADER]: CAPTURE_PIPELINE },
  });
}

/// What `invokePipeline` returns for a Lambda that predates `/pipeline`.
const NO_PIPELINE_ROUTE = Symbol("no /pipeline route");

/// Steps 1–3 of the capture pipeline, with one Lambda call doing 1 and 2:
/// `rawCapture` goes to `signing-handoff`, and the Lambda is sent a download
/// link for it and an upload link each for the original and the photo. The photo is fetched and
/// checked against the SHA-256 the Lambda reports for it, while the original
/// is copied to `originalPath` in `photo-originals` inside Storage — its bytes
/// never pass through this function, so they're not re-hashed here; the hash
/// the Lambda reported is logged.
///
/// Returns the photo; null on a Lambda error, a photo that doesn't match, or
/// a response not confirming it ran `pipeline` (each logged); or
/// `NO_PIPELINE_ROUTE` if the Lambda answered 404.
async function invokePipeline(
  rawCapture: ArrayBuffer,
  originalPath: string,
): Promise<ArrayBuffer | null | typeof NO_PIPELINE_ROUTE> {
  const callID = crypto.randomUUID();
  const inputPath = `${callID}/pipeline-in.jpg`;
  const handoffOriginalPath = `${callID}/pipeline-original.jpg`;
  const photoPath = `${callID}/pipeline-photo.jpg`;

  try {
    const [sourceURL, originalURL, photoURL] = await stageHandoff(inputPath, rawCapture, [
      handoffOriginalPath,
      photoPath,
    ]);
    const lambdaResponse = await postToLambda("pipeline", {
      source_url: sourceURL,
      original_url: originalURL,
      photo_url: photoURL,
    });
    // `Route::for_path` 404s a path it doesn't know, before reading the body.
    if (lambdaResponse.status === 404) {
      await lambdaResponse.body?.cancel();
      return NO_PIPELINE_ROUTE;
    }
    // A Lambda that ran anything but `pipeline` didn't make the photo.
    if (!(await isUsableAnswer(lambdaResponse, "pipeline", { requireRouteConfirmation: true }))) {
      return null;
    }
    const reported = await lambdaResponse.json() as { original?: Reported; photo?: Reported };
    if (!reported.original || !reported.photo) {
      console.error("Signing Lambda's /pipeline answer doesn't describe both outputs", reported);
      return null;
    }

    const [photo] = await settleBoth(
      fetchOutput(photoPath, reported.photo, "/pipeline photo"),
      keepOriginal(handoffOriginalPath, originalPath, reported.original),
    );
    return photo;
  } finally {
    cleanUpLater(callID, [inputPath, handoffOriginalPath, photoPath]);
  }
}

/// The capture pipeline for a Lambda that predates `/pipeline`: `/capture`,
/// then `/watermark` on its output while the signed capture is stored — in
/// parallel rather than after, as it's needed either way. If the watermark
/// step fails the original is still stored, and a retry overwrites it.
async function signInTwoCalls(
  rawCapture: ArrayBuffer,
  originalPath: string,
): Promise<ArrayBuffer | null> {
  const signedCapture = await invokeLambda("capture", rawCapture);
  if (!signedCapture) return null;

  const [watermarked] = await settleBoth(
    // `requireRouteConfirmation`: a Lambda that predates routing ignores the
    // path and would sign this as another capture — no watermark — and the
    // app would upload it. Only a Lambda that says it ran `watermark` is
    // believed.
    invokeLambda("watermark", signedCapture, { requireRouteConfirmation: true }),
    supabaseAdmin.storage
      .from(ORIGINALS_BUCKET)
      .upload(originalPath, signedCapture, { contentType: "image/jpeg", upsert: true })
      .then(({ error }) => {
        if (error) throw error;
      }),
  );
  return watermarked;
}

/// Copies the original from its hand-off object to `originalPath` in
/// `photo-originals`, replacing whatever an earlier attempt left there.
///
/// A copy inside Storage rather than a download and upload, so the bytes stay
/// in Storage's region. storage-js's `copy` can't overwrite — it never sends
/// `x-upsert` — so this calls the copy endpoint itself. Should the copy be
/// refused, the original is passed through this function instead, as before
/// `/pipeline`, rather than failing the photo.
async function keepOriginal(
  handoffPath: string,
  originalPath: string,
  reported: Reported,
): Promise<void> {
  const copied = await fetch(`${SUPABASE_URL}/storage/v1/object/copy`, {
    method: "POST",
    headers: {
      apikey: SUPABASE_SERVICE_ROLE_KEY,
      Authorization: `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
      "Content-Type": "application/json",
      "x-upsert": "true",
    },
    body: JSON.stringify({
      bucketId: HANDOFF_BUCKET,
      sourceKey: handoffPath,
      destinationBucket: ORIGINALS_BUCKET,
      destinationKey: originalPath,
    }),
  });
  if (copied.ok) {
    await copied.body?.cancel();
    console.log("Kept the signed capture", { path: originalPath, ...reported });
    return;
  }

  console.error(
    "Couldn't copy the signed capture inside Storage; passing it through instead",
    copied.status,
    await copied.text(),
  );
  const { data: original, error: getError } = await supabaseAdmin.storage
    .from(HANDOFF_BUCKET)
    .download(handoffPath);
  if (getError || !original) throw getError ?? new Error("no original object");
  const { error: storeError } = await supabaseAdmin.storage
    .from(ORIGINALS_BUCKET)
    .upload(originalPath, original, { contentType: "image/jpeg", upsert: true });
  if (storeError) throw storeError;
  console.log("Kept the signed capture", { path: originalPath, ...reported });
}

/// Response header in which the Lambda names the route it actually ran.
/// Mirrored in aws-signing-lambda/src/main.rs.
const LAMBDA_ROUTE_HEADER = "x-signing-route";

/// How the Lambda describes each output it wrote to the hand-off.
type Reported = { bytes?: number; sha256?: string };

/// Has the signing Lambda run `route` — "capture" (sign as-is as a capture)
/// or "watermark" (watermark a signed capture and sign the result) — on
/// `body`, and returns the result. The photo goes by the Storage hand-off,
/// never in the request: `body` is put in `signing-handoff`, and the Lambda is
/// POSTed (SigV4-signed) a download link for it and an upload link for its
/// output, which is then fetched and checked against the SHA-256 the Lambda
/// reports. Both objects are deleted whatever happens, once the response has
/// gone.
///
/// Null on a Lambda error, a result that doesn't match, or, with
/// `requireRouteConfirmation`, a response that doesn't name `route` in
/// `x-signing-route`; each is logged.
async function invokeLambda(
  route: "capture" | "watermark",
  body: ArrayBuffer,
  { requireRouteConfirmation = false } = {},
): Promise<ArrayBuffer | null> {
  const callID = crypto.randomUUID();
  const inputPath = `${callID}/${route}-in.jpg`;
  const outputPath = `${callID}/${route}-out.jpg`;

  try {
    const [sourceURL, destURL] = await stageHandoff(inputPath, body, [outputPath]);
    const lambdaResponse = await postToLambda(route, { source_url: sourceURL, dest_url: destURL });
    if (!(await isUsableAnswer(lambdaResponse, route, { requireRouteConfirmation }))) return null;
    const reported = await lambdaResponse.json() as Reported;
    return await fetchOutput(outputPath, reported, `/${route} output`);
  } finally {
    cleanUpLater(callID, [inputPath, outputPath]);
  }
}

/// Puts `input` in `signing-handoff` at `inputPath` and makes the Lambda's
/// links: a download link for it, then an upload link for each of
/// `outputPaths`, in that order. The upload links don't wait for the input.
async function stageHandoff(
  inputPath: string,
  input: ArrayBuffer,
  outputPaths: string[],
): Promise<string[]> {
  const handoff = supabaseAdmin.storage.from(HANDOFF_BUCKET);
  const source = (async () => {
    const { error: putError } = await handoff.upload(inputPath, input, {
      contentType: "image/jpeg",
    });
    if (putError) throw putError;
    const { data, error } = await handoff.createSignedUrl(inputPath, HANDOFF_LINK_SECONDS);
    if (error || !data) throw error ?? new Error("no source link");
    return data.signedUrl;
  })();
  // Upload links last two hours on Supabase's side and can't be shortened;
  // each is good for exactly one object, once (no upsert), deleted after.
  const outputs = outputPaths.map(async (path) => {
    const { data, error } = await handoff.createSignedUploadUrl(path);
    if (error || !data) throw error ?? new Error("no upload link");
    return data.signedUrl;
  });
  return await Promise.all([source, ...outputs]);
}

/// POSTs `links` to the Lambda's `route` as JSON, SigV4-signed, over the
/// storage transport.
async function postToLambda(route: string, links: Record<string, string>): Promise<Response> {
  const requestBody = JSON.stringify(links);
  const base = new URL(LAMBDA_FUNCTION_URL);
  const url = new URL(base.pathname.replace(/\/*$/, "/") + route, base);
  const signedRequest = await signer.sign(
    new HttpRequest({
      method: "POST",
      protocol: url.protocol,
      hostname: url.hostname,
      path: url.pathname,
      headers: {
        host: url.hostname,
        "content-type": "application/json",
        [TRANSPORT_HEADER]: STORAGE_TRANSPORT,
      },
      body: requestBody,
    }),
  );
  return await fetch(url, {
    method: signedRequest.method,
    headers: signedRequest.headers,
    body: requestBody,
  });
}

/// Whether the Lambda's answer to `route` can be acted on: a success, over
/// the storage hand-off, and — with `requireRouteConfirmation` — naming
/// `route` in `x-signing-route`. Logs why not.
async function isUsableAnswer(
  lambdaResponse: Response,
  route: string,
  { requireRouteConfirmation = false } = {},
): Promise<boolean> {
  if (!lambdaResponse.ok) {
    console.error(
      "Signing Lambda returned",
      lambdaResponse.status,
      "for route",
      route,
      await lambdaResponse.text(),
    );
    return false;
  }
  const ranRoute = lambdaResponse.headers.get(LAMBDA_ROUTE_HEADER);
  if (requireRouteConfirmation && ranRoute !== route) {
    console.error(
      `Signing Lambda answered /${route} without confirming it ran it`,
      `(${LAMBDA_ROUTE_HEADER}: ${ranRoute ?? "absent"}) — is the deployed Lambda older than its routes?`,
    );
    return false;
  }
  // A Lambda that predates the hand-off would have treated the JSON as the
  // photo and failed; one that answers without this header didn't use it.
  if (lambdaResponse.headers.get(TRANSPORT_HEADER) !== STORAGE_TRANSPORT) {
    console.error(`Signing Lambda answered /${route} without using the storage hand-off`);
    return false;
  }
  return true;
}

/// Downloads the hand-off object at `path` and checks it is exactly what the
/// Lambda reported writing there. Null, logged, if it isn't.
async function fetchOutput(
  path: string,
  reported: Reported,
  what: string,
): Promise<ArrayBuffer | null> {
  const { data: output, error: getError } = await supabaseAdmin.storage
    .from(HANDOFF_BUCKET)
    .download(path);
  if (getError || !output) throw getError ?? new Error("no output object");
  const result = await output.arrayBuffer();
  const digest = toHex(await crypto.subtle.digest("SHA-256", result));
  if (result.byteLength !== reported.bytes || digest !== reported.sha256) {
    console.error(
      `Signing Lambda's ${what} doesn't match what it reported`,
      { reported, got: { bytes: result.byteLength, sha256: digest } },
    );
    return null;
  }
  return result;
}

/// Deletes a call's hand-off objects once the response has gone: nothing
/// waits on it, and a failure (logged) only leaves objects in a bucket no one
/// but the service role can see.
function cleanUpLater(callID: string, paths: string[]): void {
  const cleanup = supabaseAdmin.storage
    .from(HANDOFF_BUCKET)
    .remove(paths)
    .then(({ error }) => {
      if (error) throw error;
    })
    .catch((error) => console.error("Couldn't clean up the signing hand-off", callID, error));
  // Keeps the worker alive until it's done. Absent outside Supabase's
  // runtime (a local `deno run`), where the promise just runs.
  if (typeof EdgeRuntime !== "undefined") EdgeRuntime.waitUntil(cleanup);
}

/// Supabase's Edge runtime global; not in Deno's own types.
declare const EdgeRuntime: { waitUntil(promise: Promise<unknown>): void } | undefined;

/// Awaits both, then returns both results or throws the first failure — but
/// never while the other is still running, so that nothing (a copy out of a
/// hand-off object, say) is still in flight when the caller cleans up.
async function settleBoth<A, B>(a: Promise<A>, b: Promise<B>): Promise<[A, B]> {
  await Promise.allSettled([a, b]);
  return [await a, await b];
}

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (b) => b.toString(16).padStart(2, "0")).join("");
}

function signingFailed(): Response {
  return new Response(JSON.stringify({ error: "Signing failed" }), {
    status: 502,
    headers: { "Content-Type": "application/json" },
  });
}

/// Returns a response to send instead of signing, or null to go ahead.
async function checkAppAttest(
  req: Request,
  imageData: Uint8Array,
  userId: string,
  // deno-lint-ignore no-explicit-any
  supabaseClient: any,
): Promise<Response | null> {
  const keyId = req.headers.get("X-App-Attest-Key-Id");
  const assertion = req.headers.get("X-App-Attest-Assertion");

  if (!keyId || !assertion) {
    const integrityToken = req.headers.get(PLAY_INTEGRITY_HEADER);
    if (integrityToken) {
      return await checkPlayIntegrity(integrityToken, imageData, userId, supabaseClient);
    }
    if (await isAppAttestRequired(userId, supabaseClient)) {
      return refuse(403, "attestation_required");
    }
    console.warn("Signing without App Attest", { user: userId });
    return null;
  }

  const { data: key, error: keyError } = await supabaseAdmin
    .from("app_attest_keys")
    .select("public_key, sign_count")
    .eq("key_id", keyId)
    .maybeSingle();
  if (keyError) throw keyError;
  if (!key) return refuse(403, "attestation_key_unknown");

  let signCount: number;
  try {
    ({ signCount } = await verifyAssertion({
      assertion: fromBase64(assertion),
      clientData: imageData,
      publicKeySpki: fromBase64(key.public_key),
    }));
  } catch (error) {
    if (error instanceof AppAttestError) {
      console.warn("Rejected App Attest assertion", { user: userId, keyId, reason: error.message });
      return refuse(403, "attestation_invalid");
    }
    throw error;
  }

  // Bookkeeping only — see verifyAssertion on why the counter isn't required
  // to increase. A failure here must not fail a correctly attested request.
  const { error: updateError } = await supabaseAdmin
    .from("app_attest_keys")
    .update({
      sign_count: Math.max(Number(key.sign_count), signCount),
      last_used_at: new Date().toISOString(),
    })
    .eq("key_id", keyId);
  if (updateError) console.error("Couldn't record App Attest key use", updateError);

  return null;
}

/// The Android half of `checkAppAttest`: returns a response to send instead
/// of signing, or null to go ahead.
///
/// Where it differs from App Attest, and why: a failed App Attest assertion
/// is refused even while the flag is off, because every build that sends one
/// can produce a valid one. That isn't true here — a debug build, or any
/// build on the emulator, gets a real token that Google marks unrecognized.
/// So the flag alone decides:
///   - attestation not required for this caller ⇒ any failure is logged and
///     the photo is signed, exactly as if no token had been sent;
///   - required ⇒ the token must pass in full. There is no exemption for
///     admins or for development builds: with the flag on, Android signs
///     only from a Play-installed build on a genuine device.
async function checkPlayIntegrity(
  token: string,
  imageData: Uint8Array,
  userId: string,
  // deno-lint-ignore no-explicit-any
  supabaseClient: any,
): Promise<Response | null> {
  try {
    const serviceAccount = loadServiceAccount();
    if (!serviceAccount) throw new PlayIntegrityError("Play Integrity is not configured");

    const payload = await decodeIntegrityToken(token, serviceAccount);
    evaluateVerdict(payload, { expectedRequestHash: await expectedRequestHash(imageData) });
    return null;
  } catch (error) {
    if (!(await isAppAttestRequired(userId, supabaseClient))) {
      console.warn("Signing despite a failed Play Integrity check", { user: userId, reason: String(error) });
      return null;
    }
    if (error instanceof PlayIntegrityError) {
      console.warn("Rejected Play Integrity token", { user: userId, reason: error.message });
      return refuse(403, "attestation_invalid");
    }
    // Couldn't reach Google: an outage, not a verdict. 500, and the app retries.
    throw error;
  }
}

async function isAppAttestRequired(
  userId: string,
  // deno-lint-ignore no-explicit-any
  supabaseClient: any,
): Promise<boolean> {
  const { data: flag, error: flagError } = await supabaseClient
    .from("feature_flags")
    .select("audience")
    .eq("key", REQUIRE_APP_ATTEST_FLAG)
    .maybeSingle();
  if (flagError) throw flagError;

  if (flag?.audience === "all") return true;
  if (flag?.audience !== "admin") return false;
  return await isAdmin(userId, supabaseClient);
}

// deno-lint-ignore no-explicit-any
async function isAdmin(userId: string, supabaseClient: any): Promise<boolean> {
  // Self-scoped RLS: this is the caller's own row, and the is_admin triggers
  // stop them writing it.
  const { data: profile, error: profileError } = await supabaseClient
    .from("users")
    .select("is_admin")
    .eq("id", userId)
    .single();
  if (profileError) throw profileError;
  return profile?.is_admin === true;
}

function refuse(status: number, code: string): Response {
  return new Response(JSON.stringify({ error: "Attestation check failed", code }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
