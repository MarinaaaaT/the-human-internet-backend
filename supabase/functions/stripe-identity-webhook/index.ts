// Public webhook endpoint (see supabase/config.toml — verify_jwt = false,
// Stripe is the caller, not an app user). Verifies the Stripe-Signature
// header, then flips `public.users.verification_status` on the two
// VerificationSession outcome events.
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

// The API key on this client is irrelevant to everything below: webhook
// verification is an HMAC of the raw body against the *endpoint* secret, and
// nothing here calls the Stripe API. It's the same object either way.
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, {
  httpClient: Stripe.createFetchHttpClient(),
});
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
async function verify(body: string, signature: string): Promise<Stripe.Event | null> {
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
      return event;
    } catch (_error) {
      // Wrong secret for this delivery — try the next one before giving up.
    }
  }
  return null;
}

Deno.serve(async (req) => {
  const signature = req.headers.get("Stripe-Signature");
  const body = await req.text();

  if (!signature || WEBHOOK_SECRETS.length === 0) {
    console.error("Missing Stripe-Signature header or no signing secret configured");
    return new Response("Invalid signature", { status: 400 });
  }

  const event = await verify(body, signature);
  if (!event) {
    console.error("Webhook signature verification failed against every configured secret");
    return new Response("Invalid signature", { status: 400 });
  }

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

      const { error } = await supabaseAdmin
        .from("users")
        .update({ verification_status: verificationStatus })
        .eq("id", userId);
      if (error) console.error("Failed to update verification_status", error);
    } else {
      console.error("Verification session missing metadata.user_id", session.id);
    }
  }

  return new Response(JSON.stringify({ received: true }), {
    headers: { "Content-Type": "application/json" },
  });
});
