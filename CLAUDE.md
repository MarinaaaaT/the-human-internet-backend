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
    sign-photo/            <- bridges Supabase auth -> AWS Lambda over SigV4
    stripe-identity-session/
    stripe-identity-webhook/
```

## AWS signing Lambda

Full architecture, build/deploy instructions, gotchas, and the AWS resource inventory (KMS key, IAM roles, Function URL) live in [`aws-signing-lambda/CLAUDE.md`](aws-signing-lambda/CLAUDE.md) — read that first if you're touching signing. Short version: a Rust Lambda container image signs C2PA manifests using a private key that lives entirely inside AWS KMS (`us-east-2`, account `141218266378`) and never leaves it — the production counterpart to the app repo's on-device dev-cert signing. Deployed and verified end-to-end as of 2026-08-13.

## Supabase Edge Functions

Deployed as a unit via the Supabase CLI (`supabase functions deploy`); `supabase/config.toml` covers all three.

### `sign-photo`
Forwards a raw captured JPEG to the AWS Lambda's Function URL over SigV4 and returns the signed bytes — the only bridge between Supabase and AWS. Runs with the caller's forwarded JWT (`verify_jwt = true`), so it only ever signs on behalf of the authenticated user calling it. The app calls this from `Verification/RemotePhotoSigner.swift` when the `aws_server_side_signing` feature flag is on. Requires secrets `SIGNING_LAMBDA_URL`, `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — the AWS credentials are this function's own IAM user (`c2pa-signer-invoker`), SigV4-scoped to `lambda:InvokeFunctionUrl` on exactly this one Lambda, nothing else in the AWS account. Until those secrets are set the function 500s — safe, since it's only reachable behind the feature flag.

### `stripe-identity-session`
Creates (or resumes, per Stripe's documented best practice) a Stripe Identity `VerificationSession` for the calling user and returns its hosted verification URL. Runs with the caller's forwarded JWT (`verify_jwt = true`), so reads/writes to `public.users` go through normal RLS — no elevated key needed. Only the `document` type is requested, with `options.document.require_matching_selfie: true` — **`id_number` (SSN) is deliberately never requested**, since Stripe would collect and retain the SSN itself, reversing the app's explicit no-SSN-storage design (no SSN column exists anywhere in `public.users`). Resumable statuses (`requires_input`, `processing`, `requires_action`) reuse the session id stored in `users.stripe_identity_session_id` instead of creating a duplicate. Requires secret `STRIPE_SECRET_KEY`.

### `stripe-identity-webhook`
Public endpoint (`verify_jwt = false` — Stripe is the caller, not an app user). Verifies the `Stripe-Signature` header, then on `identity.verification_session.verified` / `.requires_input` flips `public.users.verification_status` to `verified`/`failed` using the Supabase **service-role** key. This is the one place in the whole project (besides Postgres security-definer functions) where a privileged write happens outside RLS — treat any change here with the same care as a migration. Requires secrets `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SUPABASE_SERVICE_ROLE_KEY`.

**Stripe account**: `acct_1U3zoI2H64CKCopg` ("Human Internet LLC. sandbox"). **Currently blocked**: the account's Identity Dashboard application can't be completed until Human Internet LLC finishes processing with Delaware State — tracked as "Urgent - Blocked" in Notion (Task Management > Product Backlog). The app repo's `stripe_identity_verification` feature flag lets onboarding skip the broken step until this clears. There's no in-app resubmission flow yet for a `failed` status — pre-existing gap.

## Database

Schema, RLS policies, and triggers live in the shared Supabase project itself (`xpjkgngifffzdaikjakw`) — **not tracked as migration files in any repo**; changes are applied directly (dashboard or the Supabase MCP tools) and documented in the app repo's `CLAUDE.md` Database section, which remains the source of truth for table shapes, RLS, and the `is_admin` escalation guards. If that ever changes to a tracked-migrations workflow, this repo is the natural home for `supabase/migrations/`.

## Secrets

Nothing here ships a real credential in git — the AWS KMS key, the Lambda's IAM role, and every Edge Function secret above are provisioned out-of-band (`supabase secrets set`, AWS IAM/KMS console or CLI) and referenced here only by name. If you ever find a literal key in a diff, stop and rotate it.
