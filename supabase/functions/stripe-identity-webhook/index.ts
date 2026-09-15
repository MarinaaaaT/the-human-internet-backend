// Public webhook endpoint (see supabase/config.toml — verify_jwt = false,
// Stripe is the caller, not an app user). Verifies the Stripe-Signature
// header, then flips `public.users.verification_status` on the two
// VerificationSession outcome events — and, on `verified`, stores the name
// Stripe actually checked against the document.
//
// That name is the only one the public verification page may ever show. The
// page renders it beside "taken by a real, verified human", so a name the
// user typed themselves would be a claim wearing our checkmark. This is the
// one code path entitled to write it: `users.verified_first_name` /
// `verified_last_name` are guarded by the same trigger pair as `is_admin`,
// which exempts nothing but `service_role`.
//
// Uses the Supabase service-role key (unlike stripe-identity-session) since
// there's no caller JWT to scope RLS to — this is the same elevated-write
// posture CLAUDE.md documents for the Postgres security-definer functions,
// just implemented as an Edge Function instead.
//
// One endpoint serves both Stripe environments. They are separate webhook
// registrations with separate signing secrets, so a delivery is tried against
// each configured secret and the one that verifies decides which environment
// it came from — `event.livemode` then says so authoritatively, because it
// arrived inside a payload whose signature we checked.

import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@18";

// Signature verification only. The API key on this client is irrelevant to
// it — verification is an HMAC of the raw body against the *endpoint*
// secret, so any key does. Calls that reach the Stripe API go through
// `stripeFor(mode)` below, which picks the key matching the environment the
// delivery actually came from.
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, {
  httpClient: Stripe.createFetchHttpClient(),
});

type StripeMode = "live" | "test";

/// Mirrors `stripeFor` in stripe-identity-session. Built per request, since
/// constructing the test client eagerly would break the live path on a
/// deployment with no test key configured at all.
function stripeFor(mode: StripeMode): Stripe {
  const name = mode === "test" ? "STRIPE_SECRET_KEY_TEST" : "STRIPE_SECRET_KEY";
  const secret = Deno.env.get(name);
  if (!secret) {
    throw new Error(`Missing ${name} — Stripe's ${mode} environment isn't configured`);
  }
  return new Stripe(secret, { httpClient: Stripe.createFetchHttpClient() });
}

const cryptoProvider = Stripe.createSubtleCryptoProvider();

const WEBHOOK_SECRETS = [
  { mode: "live", secret: Deno.env.get("STRIPE_WEBHOOK_SECRET") },
  { mode: "test", secret: Deno.env.get("STRIPE_WEBHOOK_SECRET_TEST") },
].filter((candidate) => Boolean(candidate.secret));

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/// Returns the verified event, or null if no configured secret validates the
/// signature. Trying each is not a weakening: every attempt is a full
/// signature check, and a forged body passes none of them.
async function verify(
  body: string,
  signature: string,
): Promise<{ event: Stripe.Event; mode: StripeMode } | null> {
  for (const { mode, secret } of WEBHOOK_SECRETS) {
    try {
      const event = await stripe.webhooks.constructEventAsync(
        body,
        signature,
        secret!,
        undefined,
        cryptoProvider,
      );
      console.log(`Verified ${event.type} against the ${mode} signing secret`);
      // The mode is returned as well as logged: retrieving the session below
      // needs the key for the environment the session actually lives in, and
      // a live key cannot read a test session.
      return { event, mode: mode as StripeMode };
    } catch (_error) {
      // Wrong secret for this delivery — try the next one before giving up.
    }
  }
  return null;
}

/// The verified first/last name for a session, or null if it can't be read.
///
/// Two things force a second API call here rather than reading the webhook
/// payload. `verified_outputs` is not included on a VerificationSession by
/// default — it has to be expanded — and expanded fields are never present
/// in a webhook event body. So the payload genuinely does not carry it.
///
/// **Only the name is read.** `verified_outputs` also carries `dob` and
/// `address`, and `id_number` where that check was requested — it never is
/// here, and this project stores no SSN anywhere, by explicit design. Don't
/// widen this return type without revisiting that rule.
async function fetchVerifiedName(
  sessionId: string,
  mode: StripeMode,
): Promise<{ first: string; last: string } | null> {
  try {
    const session = await stripeFor(mode).identity.verificationSessions.retrieve(
      sessionId,
      { expand: ["verified_outputs"] },
    );
    const outputs = session.verified_outputs;
    if (!outputs) return null;
    return { first: outputs.first_name ?? "", last: outputs.last_name ?? "" };
  } catch (error) {
    console.error(`Couldn't read verified_outputs for ${sessionId}`, error);
    return null;
  }
}

Deno.serve(async (req) => {
  const signature = req.headers.get("Stripe-Signature");
  const body = await req.text();

  if (!signature || WEBHOOK_SECRETS.length === 0) {
    console.error("Missing Stripe-Signature header or no signing secret configured");
    return new Response("Invalid signature", { status: 400 });
  }

  const verified = await verify(body, signature);
  if (!verified) {
    console.error("Webhook signature verification failed against every configured secret");
    return new Response("Invalid signature", { status: 400 });
  }
  const { event, mode } = verified;

  if (
    event.type === "identity.verification_session.verified" ||
    event.type === "identity.verification_session.requires_input"
  ) {
    const session = event.data.object as Stripe.Identity.VerificationSession;
    const userId = session.metadata?.user_id;

    if (userId) {
      const verificationStatus =
        event.type === "identity.verification_session.verified" ? "verified" : "failed";

      // A test-environment event may only touch an admin. Sessions are only
      // ever created in the sandbox for admins (stripe-identity-session
      // enforces that), so this is a second lock on the same door rather than
      // a new rule — but it's the door where a sandbox scan would otherwise
      // become a real `verified`, which is the one claim the product rests
      // on. Cheap to check, and this function writes outside RLS.
      if (!event.livemode) {
        const { data: target, error: targetError } = await supabaseAdmin
          .from("users")
          .select("is_admin")
          .eq("id", userId)
          .maybeSingle();

        if (targetError || !target?.is_admin) {
          console.error(
            `Ignoring test-mode ${event.type} for non-admin user ${userId}`,
            targetError ?? "",
          );
          return new Response(JSON.stringify({ received: true }), {
            headers: { "Content-Type": "application/json" },
          });
        }
      }

      // Built as a partial rather than a fixed shape: on `requires_input`
      // there is no verified name to write, and blanking the columns would
      // throw away a good name from an earlier successful check.
      const patch: Record<string, string> = { verification_status: verificationStatus };

      if (verificationStatus === "verified") {
        const name = await fetchVerifiedName(session.id, mode);
        if (name) {
          patch.verified_first_name = name.first;
          patch.verified_last_name = name.last;
        } else {
          // The status is the claim and must land regardless. A missing name
          // costs the user the optional "show my name" row on their
          // verification page — the RPC collapses an empty name to NULL and
          // renders nothing — which is the right way to fail.
          console.error(
            `Verified ${userId} without a verified name; the status still applies`,
          );
        }
      }

      const { error } = await supabaseAdmin.from("users").update(patch).eq("id", userId);
      if (error) console.error("Failed to update verification_status", error);
    } else {
      console.error("Verification session missing metadata.user_id", session.id);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { "Content-Type": "application/json" },
  });
});
