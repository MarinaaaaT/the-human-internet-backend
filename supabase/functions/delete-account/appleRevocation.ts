// Revokes the link between a user's Apple ID and this app, as Apple expects
// of any app that offers Sign in with Apple and account deletion (App Store
// guideline 5.1.1(v)). Without it a deleted user still sees the app listed
// under Settings → Apple ID → Sign in with Apple, and a Hide My Email relay
// address keeps forwarding.
//
// Revocation needs one of the user's Apple tokens, and Supabase never kept
// any: the app signs in with `signInWithIdToken`, which consumes the ID token
// alone. So the app asks the user to confirm with Sign in with Apple once
// more right before deleting, and sends the fresh authorization code it gets
// back. That code is exchanged here for a refresh token, which is then
// revoked. Nothing is ever stored.
//
// Secrets: `APPLE_SIGNIN_KEY_ID` and `APPLE_SIGNIN_PRIVATE_KEY` (the `.p8`
// contents) — a Sign in with Apple key from the Apple Developer portal, used
// only to sign the short-lived client secret below.

import { importPKCS8, SignJWT } from "npm:jose@5";

const APPLE = "https://appleid.apple.com";
const TEAM_ID = "9HP4Y79QFR";
/// The app's bundle ID. Native Sign in with Apple issues the authorization
/// code to the bundle ID, so it — not a web Services ID — is the client.
const CLIENT_ID = "com.thehumaninternet.app";

export class AppleRevocationError extends Error {
  constructor(message: string, readonly code: string) {
    super(message);
  }
}

/// Apple's client secret: an ES256 JWT signed with the Sign in with Apple
/// key. Valid for five minutes, which is all one request needs.
async function clientSecret(): Promise<string> {
  const keyID = Deno.env.get("APPLE_SIGNIN_KEY_ID");
  const privateKey = Deno.env.get("APPLE_SIGNIN_PRIVATE_KEY");
  if (!keyID || !privateKey) {
    throw new AppleRevocationError(
      "Missing APPLE_SIGNIN_KEY_ID or APPLE_SIGNIN_PRIVATE_KEY",
      "apple_not_configured",
    );
  }
  const key = await importPKCS8(privateKey.trim(), "ES256");
  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: keyID })
    .setIssuer(TEAM_ID)
    .setSubject(CLIENT_ID)
    .setAudience(APPLE)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

/// The `sub` claim of an ID token Apple just returned to us over TLS from
/// its own token endpoint — read, not verified, since there's no party in
/// between to have forged it.
function subject(idToken: string): string | undefined {
  try {
    const payload = idToken.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(atob(payload)).sub;
  } catch {
    return undefined;
  }
}

/// Exchanges `authorizationCode` for a refresh token and revokes it.
///
/// `expectedAppleUserID` is the Apple `sub` on the Supabase account being
/// deleted. If the user confirmed with a *different* Apple ID, revoking that
/// one would leave this account's link in place while reporting success, so
/// it's refused instead.
export async function revokeAppleSignIn(
  authorizationCode: string,
  expectedAppleUserID: string,
): Promise<void> {
  const secret = await clientSecret();

  const tokenResponse = await fetch(`${APPLE}/auth/token`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: secret,
      code: authorizationCode,
      grant_type: "authorization_code",
    }),
  });
  const tokens = await tokenResponse.json().catch(() => ({}));
  if (!tokenResponse.ok || !tokens.refresh_token) {
    throw new AppleRevocationError(
      `Apple token exchange failed (${tokenResponse.status}): ${tokens.error ?? "no refresh_token"}`,
      "apple_code_invalid",
    );
  }

  if (subject(tokens.id_token ?? "") !== expectedAppleUserID) {
    throw new AppleRevocationError(
      "Confirmed with an Apple ID that doesn't own this account",
      "apple_account_mismatch",
    );
  }

  const revokeResponse = await fetch(`${APPLE}/auth/revoke`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: CLIENT_ID,
      client_secret: secret,
      token: tokens.refresh_token,
      token_type_hint: "refresh_token",
    }),
  });
  if (!revokeResponse.ok) {
    throw new AppleRevocationError(
      `Apple revoke failed (${revokeResponse.status})`,
      "apple_revoke_failed",
    );
  }
}
