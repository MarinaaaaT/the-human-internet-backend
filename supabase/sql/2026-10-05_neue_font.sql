-- "Neue Font: Pay To Enable" — PP Neue Montreal behind a feature flag.
--
-- The font files we hold today are Pangram Pangram's *Free for Personal Use*
-- release, whose EULA forbids using them in a public app or website (§2.1)
-- and making them publicly available at all (§2.6). Both app and website
-- repos are public, so the files can't live in either. They live here, in a
-- private bucket, and this flag is what decides who may download them:
--
--   off   -> nobody (not even admins)
--   admin -> admins only: personal evaluation on our own devices
--   all   -> everyone, anon included (the website). ONLY after a commercial
--            licence covering app + web has been bought and the paid files
--            have replaced the free ones in this bucket.
--
-- Swapping in the paid files later is a re-upload under the same object
-- names; no code or policy change.

insert into public.feature_flags (key, audience)
values ('neue_font', 'off')
on conflict (key) do nothing;

insert into storage.buckets (id, name, public)
values ('licensed-fonts', 'licensed-fonts', false)
on conflict (id) do nothing;

-- Without a bucket-level policy anon requests fail with a misleading
-- "Object not found" before the object policy is ever consulted (the same
-- trap the photos bucket hit). The bucket's existence isn't a secret; its
-- objects are gated below.
create policy "Anyone can see the licensed-fonts bucket"
  on storage.buckets for select
  to anon, authenticated
  using (id = 'licensed-fonts');

-- The flag *is* the licence switch. A policy expression runs as the
-- caller, and feature_flag_enabled_for() is deliberately not granted to
-- anon/authenticated (it takes any user id, so it would let anyone probe who
-- is an admin) — hence this no-argument wrapper, which only ever answers for
-- the caller. 'admin' resolves against users.is_admin; for anon auth.uid() is
-- null, so only 'all' lets the website through.
create or replace function public.can_read_licensed_fonts()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select public.feature_flag_enabled_for('neue_font', auth.uid());
$$;

revoke all on function public.can_read_licensed_fonts() from public;
grant execute on function public.can_read_licensed_fonts() to anon, authenticated, service_role;

create policy "Licensed fonts follow the neue_font flag"
  on storage.objects for select
  to anon, authenticated
  using (
    bucket_id = 'licensed-fonts'
    and public.can_read_licensed_fonts()
  );

-- Verified 2026-10-05, every audience x caller (rolled back afterwards):
--   off   -> nobody;  admin -> admins only;  all -> everyone incl. anon.

-- No insert/update/delete policies: files are managed from the dashboard
-- (service role) only.

-- The website holds only the anon key and can't read feature_flags. This
-- answers "is this flag on for everyone?" for an explicit allowlist of keys,
-- never the whole table.
create or replace function public.public_feature_flag_enabled(p_key text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select p_key in ('neue_font')
     and public.feature_flag_enabled_for(p_key, null);
$$;

revoke all on function public.public_feature_flag_enabled(text) from public;
grant execute on function public.public_feature_flag_enabled(text) to anon, authenticated, service_role;
