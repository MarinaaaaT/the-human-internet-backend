// Forwards a raw captured JPEG to the AWS Lambda that holds the real C2PA
// signing key (in AWS KMS — never in this function, never in the app) and
// returns the signed JPEG bytes. Counterpart to the on-device PhotoSigner
// in the iOS app; RemotePhotoSigner.swift calls this when
// AppState.isAWSServerSideSigningEnabled (the `aws_server_side_signing`
// feature flag) is on.
//
// Runs with the caller's own JWT forwarded by `supabase.functions.invoke`,
// so this only ever signs a photo on behalf of the authenticated user
// calling it — same auth pattern as stripe-identity-session. The AWS
// credentials below are this function's own, SigV4-scoped to
// `lambda:InvokeFunctionUrl` on exactly the one signing Lambda, nothing
// else in the AWS account.
//
// Required secrets (`supabase secrets set`): SIGNING_LAMBDA_URL,
// AWS_REGION, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY. Until those are
// set this function 500s — safe, since it's only reachable behind the
// feature flag above.

import { createClient } from "npm:@supabase/supabase-js@2";
import { SignatureV4 } from "npm:@aws-sdk/signature-v4@3";
import { HttpRequest } from "npm:@aws-sdk/protocol-http@3";
import { Sha256 } from "npm:@aws-crypto/sha256-js@5";

const LAMBDA_FUNCTION_URL = Deno.env.get("SIGNING_LAMBDA_URL")!;
const AWS_REGION = Deno.env.get("AWS_REGION")!;

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
