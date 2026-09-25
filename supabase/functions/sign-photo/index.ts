// Forwards a raw captured JPEG to the AWS Lambda that holds the real C2PA
// signing key (in AWS KMS — never in this function, never in the app) and
// returns the signed JPEG bytes. RemotePhotoSigner.swift calls this for every
// photo the iOS app uploads.
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
// Required secrets (`supabase secrets set`): SIGNING_LAMBDA_URL,
// AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY. Until those are
// set this function 500s.

import { createClient } from "npm:@supabase/supabase-js@2";
import { SignatureV4 } from "npm:@aws-sdk/signature-v4@3";
import { HttpRequest } from "npm:@aws-sdk/protocol-http@3";
import { Sha256 } from "npm:@aws-crypto/sha256-js@5";
import { AppAttestError, fromBase64, verifyAssertion } from "../_shared/appAttest.ts";

const LAMBDA_FUNCTION_URL = Deno.env.get("SIGNING_LAMBDA_URL")!;
const AWS_REGION = Deno.env.get("AWS_REGION")!;

/// Mirrors FeatureFlagAudience.includes(isAdmin:). A missing row or an
/// audience this function doesn't recognise reads as off — the rollout
/// default, since failing closed on a flag we couldn't read would stop every
/// upload from every build that predates attestation.
const REQUIRE_APP_ATTEST_FLAG = "require_app_attest";

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

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
      Deno.env.get("SUPABASE_URL")!,
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

    const imageData = new Uint8Array(await req.arrayBuffer());
    if (imageData.length === 0) {
      return new Response(JSON.stringify({ error: "Missing image data" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const refusal = await checkAppAttest(req, imageData, user.id, supabaseClient);
    if (refusal) return refusal;

    const url = new URL(LAMBDA_FUNCTION_URL);
    const signableRequest = new HttpRequest({
      method: "POST",
      protocol: url.protocol,
      hostname: url.hostname,
      path: url.pathname,
      headers: {
        host: url.hostname,
        "content-type": "application/octet-stream",
      },
      body: imageData,
    });

    const signedRequest = await signer.sign(signableRequest);

    const lambdaResponse = await fetch(url, {
      method: signedRequest.method,
      headers: signedRequest.headers,
      body: imageData,
    });

    if (!lambdaResponse.ok) {
      console.error(
        "Signing Lambda returned",
        lambdaResponse.status,
        await lambdaResponse.text(),
      );
      return new Response(JSON.stringify({ error: "Signing failed" }), {
        status: 502,
        headers: { "Content-Type": "application/json" },
      });
    }

    const signedImageData = await lambdaResponse.arrayBuffer();
    return new Response(signedImageData, {
      headers: { "Content-Type": "image/jpeg" },
    });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: "Couldn't sign photo" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});

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
  return new Response(JSON.stringify({ error: "App Attest check failed", code }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
