# the-human-internet-backend

Server-side code for [the human internet](https://the-human-internet.com): the AWS Lambda that holds the real C2PA signing key, and the Supabase Edge Functions that front it plus run Stripe Identity verification.

See [`CLAUDE.md`](CLAUDE.md) for the full picture (repo relationships, architecture, gotchas). Quick pointers:

- **AWS signing Lambda** (`aws-signing-lambda/`): Rust, needs Docker + a Rust toolchain to build. See [`aws-signing-lambda/README.md`](aws-signing-lambda/README.md) for build/deploy steps.
- **Supabase Edge Functions** (`supabase/functions/`): Deno/TypeScript, deployed with the Supabase CLI:

  ```bash
  supabase functions deploy sign-photo
  supabase functions deploy stripe-identity-session
  supabase functions deploy stripe-identity-webhook
  ```

  Requires the project to be linked (`supabase link --project-ref xpjkgngifffzdaikjakw`) and the secrets listed per-function in `CLAUDE.md` to already be set (`supabase secrets set KEY=value`).
