// Permanently deletes the calling user's account: every photo they've
// published, every stored file, their profile row and their auth identity.
// Called from the app's Settings → Account Settings → Delete Account, after
// the user has confirmed.
//
// Needs the service role, because two of the steps are out of a user's own
// reach by design: `auth.users` can only be deleted through the admin API,
// and `photo-originals` has no client-writable policy beyond DELETE. The
// caller is identified from their own forwarded JWT first, and every
// privileged operation below is scoped to that one id. The request body
// carries only an Apple authorization code (below), never a user id, so
// there's no way to name someone else.
//
// Order matters. Apple first, then the app's `PhotoRepository.delete` order:
// rows, files, identity last.
// 0. Revoke Sign in with Apple — see `appleRevocation.ts`. Required for any
//    account with an Apple identity (today, all of them): the body must
//    carry `apple_authorization_code`, fresh from the user re-confirming
//    with Apple. If it fails nothing has been deleted; if it succeeds and a
//    later step fails, signing back in with Apple re-links and the retry
//    revokes again.
// 1. `photos` rows — what `get_verification_photo()` reads, so deleting them
//    is what actually kills every shared link, immediately.
// 2. Storage objects in `photos` and `photo-originals`.
// 3. The auth user, which cascades to `public.users` (and on to anything
//    still referencing it).
// A failure at any step returns an error with the account still in place, so
// the user can simply retry — every step is idempotent. Deleting the identity
// last is what keeps that true: once it's gone, nothing could sign in to
// retry the cleanup.

import { createClient } from "npm:@supabase/supabase-js@2";
import { AppleRevocationError, revokeAppleSignIn } from "./appleRevocation.ts";

/// Every bucket that holds per-user files under a `{user_id}/` prefix.
const BUCKETS = ["photos", "photo-originals"];

/// Storage's `list` is paginated; this is its maximum page size.
const PAGE_SIZE = 1000;

const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/// Removes every object under `{userID}/` in `bucket`. Object paths are
/// always lowercased (see the app's `PhotoRepository`), and so is the id
/// `auth.getUser()` returns. Re-lists from offset 0 each pass, since each
/// pass deletes what it listed.
async function emptyFolder(bucket: string, userID: string): Promise<void> {
  while (true) {
    const { data, error } = await supabaseAdmin.storage
      .from(bucket)
      .list(userID, { limit: PAGE_SIZE });
    if (error) throw new Error(`Listing ${bucket}: ${error.message}`);
    if (!data || data.length === 0) return;

    const paths = data.map((object) => `${userID}/${object.name}`);
    const { error: removeError } = await supabaseAdmin.storage.from(bucket).remove(paths);
    if (removeError) throw new Error(`Removing from ${bucket}: ${removeError.message}`);
    if (data.length < PAGE_SIZE) return;
  }
}

Deno.serve(async (req) => {
  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405);
  }

  const supabaseClient = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
  );
  const {
    data: { user },
    error: userError,
  } = await supabaseClient.auth.getUser();
  if (userError || !user) {
    return json({ error: "Not authenticated" }, 401);
  }
  const userID = user.id.toLowerCase();

  const appleIdentity = user.identities?.find((identity) => identity.provider === "apple");
  if (appleIdentity) {
    const body = await req.json().catch(() => ({}));
    const code = typeof body.apple_authorization_code === "string" ? body.apple_authorization_code : "";
    if (!code) {
      return json({ error: "Apple confirmation required", code: "apple_code_missing" }, 400);
    }
    const appleUserID = String(appleIdentity.identity_data?.sub ?? appleIdentity.id);
    try {
      await revokeAppleSignIn(code, appleUserID);
    } catch (error) {
      console.error(`delete-account: Apple revocation failed for ${userID}:`, error);
      const reason = error instanceof AppleRevocationError ? error.code : "apple_revoke_failed";
      // The user's own fault (a stale code, the wrong Apple ID) is a 400 the
      // app can explain; anything else is ours.
      const status = reason === "apple_code_invalid" || reason === "apple_account_mismatch" ? 400 : 500;
      return json({ error: "Couldn't confirm with Apple", code: reason }, status);
    }
  }

  try {
    const { error: photosError } = await supabaseAdmin
      .from("photos")
      .delete()
      .eq("user_id", userID);
    if (photosError) throw new Error(`Deleting photos rows: ${photosError.message}`);

    for (const bucket of BUCKETS) {
      await emptyFolder(bucket, userID);
    }

    const { error: deleteError } = await supabaseAdmin.auth.admin.deleteUser(userID);
    if (deleteError) throw new Error(`Deleting auth user: ${deleteError.message}`);

    console.log(`Deleted account ${userID}`);
    return json({ deleted: true });
  } catch (error) {
    console.error(`delete-account failed for ${userID}:`, error);
    return json({ error: "Couldn't delete account" }, 500);
  }
});
