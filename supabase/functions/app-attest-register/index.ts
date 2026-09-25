// Registers an app install's App Attest key — step two of the handshake
// `app-attest-challenge` starts. Verifies Apple's attestation object against
// the challenge we issued this user (see `_shared/appAttest.ts` for every
// check), then stores the attested public key under its key id so
// `sign-photo` can verify each later assertion from that install.
//
// Runs with the caller's JWT (`verify_jwt = true`). Keys and challenges are
// read and written with the service role; both tables have RLS on and no
// policies, so nothing here is reachable through PostgREST.
//
// Body: { "keyId": base64, "attestation": base64, "challenge": base64 }
// Responses: 200 { environment } | 400 malformed | 401 not signed in |
//            403 attestation rejected (the app discards the key and starts
//            over) | 500.

import { createClient } from "npm:@supabase/supabase-js@2";
import { AppAttestError, fromBase64, toBase64, verifyAttestation } from "../_shared/appAttest.ts";

/// Mirrors `app-attest-challenge`.
const CHALLENGE_TTL_MS = 5 * 60 * 1000;

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  try {
    const supabaseClient = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } },
    );
    const { data: { user }, error: userError } = await supabaseClient.auth.getUser();
    if (userError || !user) {
      return json({ error: "Not authenticated" }, 401);
    }

    let body: { keyId?: unknown; attestation?: unknown; challenge?: unknown };
    try {
      body = await req.json();
    } catch {
      return json({ error: "Body must be JSON" }, 400);
    }
    const { keyId, attestation, challenge } = body;
    if (typeof keyId !== "string" || typeof attestation !== "string" || typeof challenge !== "string") {
      return json({ error: "keyId, attestation and challenge are required" }, 400);
    }

    // Redeem the challenge: delete-returning, so it can be used exactly once
    // even by two racing requests, and only by the user it was issued to.
    const { data: redeemed, error: redeemError } = await supabaseAdmin
      .from("app_attest_challenges")
      .delete()
      .eq("challenge", challenge)
      .eq("user_id", user.id)
      .select("created_at");
    if (redeemError) throw redeemError;
    const issuedAt = redeemed?.[0]?.created_at;
    if (!issuedAt || Date.now() - new Date(issuedAt).getTime() > CHALLENGE_TTL_MS) {
      return json({ error: "Challenge is unknown, expired or already used" }, 403);
    }

    let verified;
    try {
      verified = await verifyAttestation({
        attestation: fromBase64(attestation),
        // The app attests over SHA256 of the challenge's decoded bytes.
        challenge: fromBase64(challenge),
        keyId,
      });
    } catch (error) {
      if (error instanceof AppAttestError) {
        console.warn("Rejected App Attest attestation", { user: user.id, reason: error.message });
        return json({ error: "Attestation rejected" }, 403);
      }
      throw error;
    }

    // A key id is the hash of its public key, so a second registration of the
    // same id can only ever carry the same key; upsert makes an app retry
    // after a lost response harmless.
    const { error: upsertError } = await supabaseAdmin
      .from("app_attest_keys")
      .upsert({
        key_id: keyId,
        public_key: toBase64(verified.publicKeySpki),
        environment: verified.environment,
        registered_by: user.id,
      }, { onConflict: "key_id", ignoreDuplicates: true });
    if (upsertError) throw upsertError;

    return json({ environment: verified.environment });
  } catch (error) {
    console.error(error);
    return json({ error: "Couldn't register key" }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
