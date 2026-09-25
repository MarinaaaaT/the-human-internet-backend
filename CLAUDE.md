# The Human Internet — Backend

Server-side code for "the human internet": the AWS Lambda that holds the real C2PA signing key, and the Supabase Edge Functions that front it and run Stripe Identity verification. Split out of `the-human-internet-app` on 2026-08-14 once it became clear this code had no build-time coupling to the iOS app and was already deployed independently — see that repo's git history (`ecd906b`, `2e8d6ec`, `4735ef9`) for how it got here, preserved via `git filter-repo`.

**Three sibling repos, one Supabase project** (id `xpjkgngifffzdaikjakw`, "The Human Internet"):
- `the-human-internet-app` — the iOS app. Calls the Edge Functions below by name via `supabase.functions.invoke`; never talks to AWS directly.
- `the-human-internet-website` — Next.js marketing site + signed-out verification page. Reads the same Supabase project with the anon key.
- `the-human-internet-backend` (this repo) — everything that runs on a server, not in a distributable app bundle.

There's no code sharing across the boundary to `the-human-internet-app` — only a documented *behavioral* contract: the C2PA manifest JSON shape must stay byte-for-byte identical between this repo's `aws-signing-lambda/src/manifest.rs` and the app repo's `Verification/PhotoSigner.swift`, kept in sync by hand (no shared source, same v2 `digitalSourceType` camelCase gotcha hits both).

## Repo layout

```
aws-signing-lambda/       <- Rust Lambda, KMS-backed C2PA signing (own CLAUDE.md/README below)
supabase/
  config.toml
  functions/
    _shared/appAttest.ts   <- App Attest attestation/assertion verification (+ tests)
    sign-photo/            <- bridges Supabase auth -> AWS Lambda over SigV4, App Attest-gated
    app-attest-challenge/  <- App Attest key registration, step 1
    app-attest-register/   <- App Attest key registration, step 2
    stripe-identity-session/
    stripe-identity-webhook/
```

## AWS signing Lambda

Full architecture, build/deploy instructions, gotchas, and the AWS resource inventory (KMS key, IAM roles, Function URL) live in [`aws-signing-lambda/CLAUDE.md`](aws-signing-lambda/CLAUDE.md) — read that first if you're touching signing. Short version: a Rust Lambda container image signs C2PA manifests using a private key that lives entirely inside AWS KMS (`us-east-2`, account `141218266378`) and never leaves it — the production counterpart to the app repo's on-device dev-cert signing. Deployed and verified end-to-end as of 2026-08-13.

## Supabase Edge Functions

Deployed as a unit via the Supabase CLI (`supabase functions deploy`); `supabase/config.toml` covers all five.

### `sign-photo`
Forwards a captured JPEG to the AWS Lambda's Function URL over SigV4 and returns the signed bytes — the only bridge between Supabase and AWS, and the app's only signer (`Verification/RemotePhotoSigner.swift`; the on-device fallback and the `aws_server_side_signing` flag that chose between them were removed from the app on 2026-09-23). Runs with the caller's forwarded JWT (`verify_jwt = true`), so it only ever signs on behalf of the authenticated user calling it. Requires secrets `SIGNING_LAMBDA_URL`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — the AWS credentials are this function's own IAM user (`c2pa-signer-invoker`), SigV4-scoped to `lambda:InvokeFunctionUrl` on exactly this one Lambda, nothing else in the AWS account. Without those secrets the function 500s, which surfaces to users as a photo stuck in "still being verified" and then a failed-upload row in the app's pending banner (`PhotoUploadQueue` retries rather than losing it, so it recovers once the function is healthy again).

**App Attest gates it** (added 2026-09-25). Before that, a session token alone was enough to get *any* bytes signed as a `digitalCapture` — an AI image sent with curl came back genuinely signed. Now a request may carry `X-App-Attest-Key-Id` + `X-App-Attest-Assertion` (base64): an assertion over **the exact request body**, from a key `app-attest-register` verified came from our app (`APP_ID` = `9HP4Y79QFR.com.thehumaninternet.app`) on real Apple hardware.
- Assertion present ⇒ it must verify or nothing is signed (`403`, `code: attestation_key_unknown | attestation_invalid` — the app discards its key, re-registers and retries once).
- Assertion absent ⇒ refused (`403`, `code: attestation_required`) only if the **`require_app_attest`** flag resolves on for the caller (`all`, or `admin` + `users.is_admin`); otherwise signed and logged. It starts `off` because every build shipped before this sends no assertion — setting `all` stops those builds uploading, and also stops anyone uploading from the Simulator, which has no App Attest.
- The assertion counter is recorded but **not** required to increase: the clientData is the image itself, so a replay only re-signs bytes its holder already had, while the app signs two photos concurrently and their requests can arrive out of counter order.
- What it proves is the request's origin, not the pixels: a jailbroken device can still hook the capture path. Binding the assertion to the raw capture at the shutter, and producing edits/watermark server-side, is the follow-on work (Notion Tech Debt: "[Provenance 2–4/4]").

### `app-attest-challenge` / `app-attest-register`
The once-per-install handshake behind the above (app side: `Verification/AppAttestService.swift`). `app-attest-challenge` issues 32 random bytes tied to the calling user; the app has the Secure Enclave attest a new key over `SHA256(challenge)` and posts `{keyId, attestation, challenge}` to `app-attest-register`, which redeems the challenge (single use, 5-minute TTL, same user) and runs Apple's full attestation check in `_shared/appAttest.ts` — certificate chain to the **pinned** Apple App Attestation Root CA, embedded nonce, key id = hash of the public key, our app id, zero counter, App Attest AAGUID. Both environments are accepted (`development` keys come only from development-signed builds of our own team, bound by `APP_ID` like production ones); which one is recorded per key. Both functions `verify_jwt = true` and write with the service role.

`_shared/appAttest_test.ts` runs the verifier against **real** Apple-issued attestations and an assertion (`_shared/testdata/`, MIT, from `node-app-attest`) plus tampered and synthetic cases: `deno test --allow-read --allow-env supabase/functions/_shared/appAttest_test.ts`.

### `stripe-identity-session`
Creates (or resumes, per Stripe's documented best practice) a Stripe Identity `VerificationSession` for the calling user and returns its hosted verification URL. Runs with the caller's forwarded JWT (`verify_jwt = true`), so reads/writes to `public.users` go through normal RLS — no elevated key needed. Only the `document` type is requested, with `options.document.require_matching_selfie: true` — **`id_number` (SSN) is deliberately never requested**, since Stripe would collect and retain the SSN itself, reversing the app's explicit no-SSN-storage design (no SSN column exists anywhere in `public.users`). The session's `return_url` **must be http(s)** — `thehumaninternet://identity-verification-return` was rejected with `url_invalid` and failed every session creation until it became `https://the-human-internet.com/identity-verification-return` on 2026-08-29. Nothing is served at that path: the app's WKWebView recognises the URL and cancels the navigation before it loads, so the two constants are a contract (app side: `StripeIdentityHostPolicy.isReturnURL`) whose drift is silent.

Resumable statuses (`requires_input`, `processing`, `requires_action`) reuse the session id stored in `users.stripe_identity_session_id` instead of creating a duplicate — but that retrieve is wrapped in a try/catch, because a session id belongs to the environment that created it and 404s in the other one; the failure is expected and falls through to creating a fresh session.

**This function chooses the Stripe environment, and the client never does.** Live unless *both* the `stripe_identity_test_mode` feature flag resolves on (`audience` in `all`/`admin`) *and* the caller's `users.is_admin` is true — both re-read here through the caller's JWT, mirroring `AppState.isStripeIdentityTestModeEnabled` in the app. The app's copy of that decision only drives what its UI shows; a client that lied about it would still get a live session. The `is_admin` conjunct is what makes `all` on that flag harmless if it's ever written straight into the table (the app's developer menu refuses to set it). Requires secrets `STRIPE_SECRET_KEY` and — only if the test environment is used — `STRIPE_SECRET_KEY_TEST`; each is read lazily, so a deployment without the test key still serves live sessions normally.

### `stripe-identity-webhook`
Public endpoint (`verify_jwt = false` — Stripe is the caller, not an app user). Verifies the `Stripe-Signature` header, then on `identity.verification_session.verified` / `.requires_input` flips `public.users.verification_status` to `verified`/`failed` using the Supabase **service-role** key. This is the one place in the whole project (besides Postgres security-definer functions) where a privileged write happens outside RLS — treat any change here with the same care as a migration. Requires secrets `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SUPABASE_SERVICE_ROLE_KEY`, plus `STRIPE_WEBHOOK_SECRET_TEST` if the test environment is in use.

**One endpoint, both environments.** Live and test are separate webhook registrations in Stripe with separate signing secrets, so a delivery is tried against each configured secret in turn and the one that verifies tells us where it came from. Trying both isn't a weakening — each attempt is a full HMAC check and a forged body passes neither — and once a payload is verified, `event.livemode` inside it can be trusted. A `livemode: false` event is applied **only if its target user is an admin**; otherwise it's logged and dropped. That's redundant with `stripe-identity-session` only creating sandbox sessions for admins, and deliberately so: this is the exact spot where a sandbox document scan would otherwise turn into a real `verified`, written outside RLS.

Still missing (tracked on Notion's Tech Debt board as **[T2]**): no `event.id` dedupe and no ordering guard, so a redelivered or late `requires_input` arriving after a `verified` will downgrade a legitimately verified user. Worth fixing before real traffic.

**Stripe account**: `acct_1U3zoI2H64CKCopg` ("Human Internet LLC. sandbox"). The Identity Dashboard application was completed on 2026-08-29, clearing the long-standing blocker (Delaware LLC processing → business bank account). What remains before either environment works end-to-end is configuration, not code: the four Stripe secrets above set via `supabase secrets set`, and the webhook endpoint registered — separately in live and in sandbox — for `identity.verification_session.verified` and `.requires_input`. Onboarding stays behind the app's `stripe_identity_verification` flag (currently `off`) until that's done. There's no in-app resubmission flow yet for a `failed` status, and `in_progress` is a dead end for the same reason — both tracked in Notion (Product Backlog).

## Database

Schema, RLS policies, and triggers live in the shared Supabase project itself (`xpjkgngifffzdaikjakw`) — **not tracked as migration files in any repo**; changes are applied directly (dashboard or the Supabase MCP tools) and documented in the app repo's `CLAUDE.md` Database section, which remains the source of truth for table shapes, RLS, and the `is_admin` escalation guards. If that ever changes to a tracked-migrations workflow, this repo is the natural home for `supabase/migrations/`.

**App Attest tables** (`supabase/sql/2026-09-25_app_attest.sql`, the record of what to apply): `app_attest_keys` (key id → attested public key, environment, highest counter seen) and `app_attest_challenges` (single-use registration challenges). Both have RLS **on with no policies** — reachable only by the Edge Functions' service role, never through PostgREST.

## Secrets

Nothing here ships a real credential in git — the AWS KMS key, the Lambda's IAM role, and every Edge Function secret above are provisioned out-of-band (`supabase secrets set`, AWS IAM/KMS console or CLI) and referenced here only by name. If you ever find a literal key in a diff, stop and rotate it.
