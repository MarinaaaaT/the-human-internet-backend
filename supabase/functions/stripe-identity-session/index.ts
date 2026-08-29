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
//
// Two Stripe environments are reachable from here, and *this function*
// decides which one — never the caller. The app has a matching
// `AppState.isStripeIdentityTestModeEnabled`, but it only drives what the UI
// shows: a client that lied about it would still get a live session, because
// the flag and the is_admin check are both re-read here. A sandbox
// verification proves nothing about a real person, so "which environment" is
// exactly the kind of decision that can't be delegated to a client.

import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@18";

// Where Stripe sends the browser once the user submits. **Must be http(s)**
// — Stripe validates this parameter and rejects the app's
// `thehumaninternet://` scheme outright with `url_invalid`, failing session
// creation before it starts. Nothing is served at this path and nothing needs
// to be: the app's WKWebView recognises the URL and cancels the navigation
// before it loads (StripeIdentityHostPolicy.isReturnURL). Those two constants
// are a contract, and drift between them is silent — Stripe finishes, the web
// view just never dismisses.
const RETURN_URL = "https://the-human-internet.com/identity-verification-return";

/// Mirrors FeatureFlagKey.stripeIdentityTestMode in the iOS app.
const TEST_MODE_FLAG = "stripe_identity_test_mode";

/// Mirrors FeatureFlagAudience.includes(isAdmin:) for an admin caller. An
/// audience this function doesn't recognise — including a missing row — is
/// absent from this set and so reads as off, the same fallback the app
/// applies.
const TEST_MODE_AUDIENCES = new Set(["all", "admin"]);

// Statuses worth reusing (retrieving refreshes the short-lived `url`) rather
// than creating a brand new session, per Stripe's VerificationSession best
// practices.
const RESUMABLE_STATUSES = new Set(["requires_input", "processing", "requires_action"]);

type StripeMode = "live" | "test";

/// Built per request rather than once at module scope: the two environments
/// need different keys, and constructing the test client eagerly would make
/// the live path fail on a deployment that has no test key set at all.
function stripeFor(mode: StripeMode): Stripe {
  const name = mode === "test" ? "STRIPE_SECRET_KEY_TEST" : "STRIPE_SECRET_KEY";
  const secret = Deno.env.get(name);
  if (!secret) {
    throw new Error(`Missing ${name} — Stripe's ${mode} environment isn't configured`);
  }
  return new Stripe(secret, { httpClient: Stripe.createFetchHttpClient() });
}

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

    // `is_admin` is readable here because users RLS is self-scoped — this is
    // the caller's own row. It is not writable by them: two triggers on
    // public.users revert any client-side change to it.
    const { data: profile, error: profileError } = await supabaseClient
      .from("users")
      .select("stripe_identity_session_id, is_admin")
      .eq("id", user.id)
      .single();
    if (profileError) throw profileError;

    const { data: flag, error: flagError } = await supabaseClient
      .from("feature_flags")
      .select("audience")
      .eq("key", TEST_MODE_FLAG)
      .maybeSingle();
    if (flagError) throw flagError;

    // Both conjuncts matter. The audience alone isn't enough: `all` written
    // straight into the table (bypassing the developer menu, which refuses
    // it) would otherwise put every user in the sandbox.
    const mode: StripeMode = profile?.is_admin && TEST_MODE_AUDIENCES.has(flag?.audience ?? "off")
      ? "test"
      : "live";
    const stripe = stripeFor(mode);

    let session: Stripe.Identity.VerificationSession | null = null;

    if (profile?.stripe_identity_session_id) {
      // A stored id belongs to whichever environment created it, and the two
      // don't share objects — so after an admin switches environments this
      // retrieve 404s. That's expected, not an error worth failing the
      // request over: fall through and create a fresh session in the
      // environment now in force.
      try {
        const existing = await stripe.identity.verificationSessions.retrieve(
          profile.stripe_identity_session_id,
        );
        if (RESUMABLE_STATUSES.has(existing.status)) {
          session = existing;
        }
      } catch (error) {
        console.log(
          `Couldn't resume session ${profile.stripe_identity_session_id} in ${mode} mode, creating a new one`,
          error instanceof Error ? error.message : error,
        );
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

    console.log(`Identity session ${session.id} for ${user.id} in ${mode} mode`);

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
