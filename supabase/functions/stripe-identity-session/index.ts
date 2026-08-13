// Creates (or resumes) a Stripe Identity VerificationSession for the calling
// user and returns its hosted verification URL.
//
// Runs with the caller's own JWT forwarded by `supabase.functions.invoke`, so
// reads/writes to `public.users` go through normal RLS — no service-role key
// needed here (see stripe-identity-webhook for the one function that does).
//
// Only `document` + `require_matching_selfie` checks are requested — no
// `id_number` (SSN) session type. The app never sends SSNs to Stripe by
// design; see the-human-internet/Onboarding/IdentityVerificationView.swift.

import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@18";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, {
  httpClient: Stripe.createFetchHttpClient(),
});

const RETURN_URL = "thehumaninternet://identity-verification-return";

// Statuses worth reusing (retrieving refreshes the short-lived `url`) rather
// than creating a brand new session, per Stripe's VerificationSession best
// practices.
const RESUMABLE_STATUSES = new Set(["requires_input", "processing", "requires_action"]);

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

    const { data: profile, error: profileError } = await supabaseClient
      .from("users")
      .select("stripe_identity_session_id")
      .eq("id", user.id)
      .single();
    if (profileError) throw profileError;

    let session: Stripe.Identity.VerificationSession | null = null;

    if (profile?.stripe_identity_session_id) {
      const existing = await stripe.identity.verificationSessions.retrieve(
        profile.stripe_identity_session_id,
      );
      if (RESUMABLE_STATUSES.has(existing.status)) {
        session = existing;
      }
    }

    if (!session) {
      session = await stripe.identity.verificationSessions.create({
        type: "document",
        options: { document: { require_matching_selfie: true } },
        metadata: { user_id: user.id },
        return_url: RETURN_URL,
      });

      const { error: updateError } = await supabaseClient
        .from("users")
        .update({ stripe_identity_session_id: session.id })
        .eq("id", user.id);
      if (updateError) throw updateError;
    }

    return new Response(JSON.stringify({ url: session.url }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    console.error(error);
    return new Response(JSON.stringify({ error: "Couldn't start verification" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
});
