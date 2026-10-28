// Signs the caller into the shared demo account, resetting it first — the
// app's `thehumaninternet://demo` link, which skips Sign in with Apple.
//
// Public (`verify_jwt = false`): whoever opens the link has no session yet,
// and the link itself is public, so there is nothing a JWT would prove. That
// is acceptable only because of what the demo account can't do:
// - Its photos are flagged on both verification pages ("human authenticity is
//   not guaranteed") through `users.is_demo`, which only the service role can
//   write (`supabase/sql/2026-10-28_demo_account.sql`).
// - It auto-verifies without Stripe (`stripe-identity-session`), but a
//   verified demo account still reads as a demo account everywhere.
// - It is never an admin; the reset below writes `is_admin = false`.
//
// Every call resets **everything about the account except its photos**:
// profile, privacy, verification status and the "verified" name, page
// customization, Photo Fingerprint, and the onboarding step, which goes back
// to `profile` so the app walks through onboarding again with the username
// prefilled. `photos` rows and Storage objects are left alone.
//
// The account is one shared identity, created on first use: an email user
// with no password that nobody can sign in to except through here. The
// session is minted by generating a magic link with the admin API and
// redeeming its token hash on the spot — nothing is emailed, and there is no
// demo password to keep secret or rotate.

import { createClient } from "npm:@supabase/supabase-js@2";

/// The demo identity. Not a real inbox: nothing is ever sent to it.
const DEMO_EMAIL = "demo@the-human-internet.com";

/// What the profile step opens prefilled with. If a real user has taken it
/// (usernames are unique case-insensitively), the reset falls back to an
/// empty username and the step opens blank rather than failing.
const DEMO_USERNAME = "demo account";

/// Every column of `public.users` but `id` and `created_at`, at the value a
/// brand-new account has — including the verified name and date that
/// `stripe-identity-session`'s demo auto-verification writes. Written under
/// the service role, so the triggers that guard `verification_status`, the
/// verified name, `is_admin` and `is_demo` let it through.
const RESET_ROW = {
  username: DEMO_USERNAME,
  profile_icon_index: 0,
  privacy: "Public",
  verification_status: "unverified",
  onboarding_step: "profile",
  stripe_identity_session_id: null,
  is_admin: false,
  is_demo: true,
  show_identity: false,
  social_links: [],
  verified_first_name: "",
  verified_last_name: "",
  identity_verified_at: null,
  display_first_name: "",
  display_last_name: "",
  phone_number: "",
  watermark_enabled: true,
};

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false, autoRefreshToken: false } },
);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/// The demo user's id, creating the auth identity on first use. Its
/// `public.users` row is written by `resetDemoRow`, not here.
async function demoUserID(): Promise<string> {
  const { data: rows, error: lookupError } = await supabaseAdmin
    .from("users")
    .select("id")
    .eq("is_demo", true)
    .limit(1);
  if (lookupError) throw lookupError;
  if (rows && rows.length > 0) return rows[0].id;

  const { data: created, error: createError } = await supabaseAdmin.auth.admin.createUser({
    email: DEMO_EMAIL,
    email_confirm: true,
  });
  if (created?.user) return created.user.id;

  // Created before, but its row was never written (or was deleted): find it
  // through a link, which names the user without having to page through
  // every auth user.
  const { data: link, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
    type: "magiclink",
    email: DEMO_EMAIL,
  });
  if (link?.user) return link.user.id;
  throw createError ?? linkError ?? new Error("Couldn't create the demo user");
}

/// Writes the reset row. A username conflict means a real user now holds
/// `DEMO_USERNAME`; the demo account gives it up rather than failing.
async function resetDemoRow(userID: string): Promise<void> {
  const { error } = await supabaseAdmin.from("users").upsert({ id: userID, ...RESET_ROW });
  if (!error) return;
  if (error.code !== "23505") throw error;
  console.log(`"${DEMO_USERNAME}" is taken; resetting the demo account with no username`);
  const { error: retryError } = await supabaseAdmin
    .from("users")
    .upsert({ id: userID, ...RESET_ROW, username: "" });
  if (retryError) throw retryError;
}

/// A fresh session for the demo user: a magic link generated (not sent) and
/// redeemed here. Each call is a new session, so two people demoing at once
/// each get their own tokens for the same account.
async function demoSession(): Promise<{ access_token: string; refresh_token: string }> {
  const { data: link, error: linkError } = await supabaseAdmin.auth.admin.generateLink({
    type: "magiclink",
    email: DEMO_EMAIL,
  });
  if (linkError || !link?.properties?.hashed_token) {
    throw linkError ?? new Error("generateLink returned no token");
  }

  // Redeemed with the anon key, as a client would: the service-role client
  // must never end up holding a user session.
  const supabaseAnon = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { auth: { persistSession: false, autoRefreshToken: false } },
  );
  const { data, error } = await supabaseAnon.auth.verifyOtp({
    token_hash: link.properties.hashed_token,
    type: "magiclink",
  });
  if (error || !data.session) throw error ?? new Error("verifyOtp returned no session");
  return { access_token: data.session.access_token, refresh_token: data.session.refresh_token };
}

Deno.serve(async (req) => {
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405);
  try {
    const userID = await demoUserID();
    await resetDemoRow(userID);
    const session = await demoSession();
    console.log(`Demo account ${userID} reset and signed in`);
    return json(session);
  } catch (error) {
    console.error(error);
    return json({ error: "Couldn't open the demo account" }, 500);
  }
});
