// Public webhook endpoint (see supabase/config.toml — verify_jwt = false,
// Stripe is the caller, not an app user). Verifies the Stripe-Signature
// header, then flips `public.users.verification_status` on the two
// VerificationSession outcome events.
//
// Uses the Supabase service-role key (unlike stripe-identity-session) since
// there's no caller JWT to scope RLS to — this is the same elevated-write
// posture CLAUDE.md documents for the Postgres security-definer functions,
// just implemented as an Edge Function instead.

import { createClient } from "npm:@supabase/supabase-js@2";
import Stripe from "npm:stripe@18";

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!, {
  httpClient: Stripe.createFetchHttpClient(),
});
const cryptoProvider = Stripe.createSubtleCryptoProvider();

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

Deno.serve(async (req) => {
  const signature = req.headers.get("Stripe-Signature");
  const body = await req.text();

  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body,
      signature!,
      Deno.env.get("STRIPE_WEBHOOK_SECRET")!,
      undefined,
      cryptoProvider,
    );
  } catch (error) {
    console.error("Webhook signature verification failed", error);
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
