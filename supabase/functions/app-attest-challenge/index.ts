// Issues a single-use challenge for App Attest key registration — step one
// of the two-call handshake the iOS app runs once per install
// (`Verification/AppAttestService.swift`): fetch a challenge here, have the
// Secure Enclave attest a fresh key over it, then hand the attestation to
// `app-attest-register`. The challenge is what stops an attestation captured
// once from being replayed to register the same key again elsewhere.
//
// Runs with the caller's JWT (`verify_jwt = true`) and ties the challenge to
// that user, so only they can redeem it. The row itself is written with the
// service role: `app_attest_challenges` has RLS on and no policies at all.
//
// Required secrets: none beyond the SUPABASE_* ones every function gets.

import { createClient } from "npm:@supabase/supabase-js@2";
import { toBase64 } from "../_shared/appAttest.ts";

/// How long an issued challenge stays redeemable. Mirrored in
/// `app-attest-register`, which is the side that enforces it.
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

    const challenge = toBase64(crypto.getRandomValues(new Uint8Array(32)));
    const { error: insertError } = await supabaseAdmin
      .from("app_attest_challenges")
      .insert({ challenge, user_id: user.id });
    if (insertError) throw insertError;

    // Opportunistic cleanup, so abandoned handshakes don't accumulate. Not
    // load-bearing: `app-attest-register` checks expiry itself.
    const cutoff = new Date(Date.now() - CHALLENGE_TTL_MS).toISOString();
    const { error: cleanupError } = await supabaseAdmin
      .from("app_attest_challenges")
      .delete()
      .lt("created_at", cutoff);
    if (cleanupError) console.error("Challenge cleanup failed", cleanupError);

    return json({ challenge });
  } catch (error) {
    console.error(error);
    return json({ error: "Couldn't issue challenge" }, 500);
  }
});

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
