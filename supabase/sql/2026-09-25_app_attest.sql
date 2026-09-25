-- App Attest: device keys + registration challenges + the enforcement flag.
--
-- Not a tracked migration (schema in this project is applied by hand — see
-- CLAUDE.md → Database); this file is the record of what was applied, to be
-- run once in the SQL editor or via the Supabase MCP. Purely additive: two
-- new tables nothing reads yet, and a flag row that starts `off`.

-- One row per app install's App Attest key. Written and read only by the
-- `app-attest-register` and `sign-photo` Edge Functions under the service
-- role: RLS is on with no policies, so neither anon nor authenticated can see
-- or touch it through PostgREST.
create table public.app_attest_keys (
  key_id        text primary key,               -- base64, as DCAppAttestService hands it out
  public_key    text not null,                  -- base64 SPKI DER of the attested P-256 key
  environment   text not null check (environment in ('production', 'development')),
  sign_count    bigint not null default 0,      -- highest assertion counter seen
  registered_by uuid references auth.users (id) on delete set null,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);
alter table public.app_attest_keys enable row level security;

-- Single-use challenges for attestation, issued by `app-attest-challenge` and
-- consumed (deleted) by `app-attest-register`. Service role only, as above.
create table public.app_attest_challenges (
  challenge  text primary key,                  -- base64 of 32 random bytes
  user_id    uuid not null references auth.users (id) on delete cascade,
  created_at timestamptz not null default now()
);
alter table public.app_attest_challenges enable row level security;
create index app_attest_challenges_created_at_idx on public.app_attest_challenges (created_at);

-- On ⇒ `sign-photo` refuses to sign for that user without a valid App Attest
-- assertion. Starts `off` (verify-if-present, log-if-absent) because every
-- build already in the wild sends no assertion; `admin` dark-launches the
-- requirement on admin accounts; `all` only once no unattesting build is in
-- use. Resolved server-side only.
insert into public.feature_flags (key, audience)
values ('require_app_attest', 'off')
on conflict (key) do nothing;
