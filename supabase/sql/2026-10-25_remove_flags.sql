-- Removes three rolled-out feature flags from the code that reads them, and
-- splits the Stripe Identity flag in two.
--
-- Not a tracked migration (schema in this project is applied by hand — see
-- CLAUDE.md → Database); this file is the record of what was applied, to be
-- run once in the SQL editor or via the Supabase MCP. Changes nothing anyone
-- sees: every flag removed here was already `all`.
--
-- `custom_verification_pages`, `require_app_attest` and
-- `server_side_watermark` stop being read by the database and by
-- `sign-photo`, and the iOS app stops reading them too. Their rows stay, at
-- `all`, because builds already installed still read them: with a row
-- missing, an older iOS build hides the verification-page settings and goes
-- back to watermarking on device, and the Android app reads
-- `server_side_watermark` the same way. Delete them once no such build is in
-- use. Until then nothing should change them.
--
-- `stripe_identity_verification` stays for the same reason (older builds
-- read it for both the onboarding step and the Settings button). Newer
-- builds read the two flags below instead.

-- The verification-page customization (verified name, its date, social
-- handles) is published whenever the owner is verified, Public (web only)
-- and, for the name, has `show_identity` on. The `custom_verification_pages`
-- conjunct is gone; nothing else changes, so `create or replace` keeps the
-- grants.
create or replace function public.get_verification_photo(p_lookup text)
returns table (
  storage_path text,
  username text,
  captured_at timestamptz,
  is_public boolean,
  is_verified boolean,
  display_name text,
  identity_verified_at timestamptz,
  social_links jsonb
)
language sql
security definer
set search_path to 'public'
as $function$
  select
    case when u.privacy = 'Public' then p.storage_path end,
    case when u.privacy = 'Public' then u.username end,
    p.captured_at,
    (u.privacy = 'Public'),
    (u.verification_status = 'verified'),
    case
      when u.privacy = 'Public'
       and u.verification_status = 'verified'
       and u.show_identity
      then nullif(btrim(u.verified_first_name || ' ' || u.verified_last_name), '')
    end,
    case
      when u.privacy = 'Public'
       and u.verification_status = 'verified'
       and u.show_identity
      then u.identity_verified_at
    end,
    case
      when u.privacy = 'Public'
       and u.verification_status = 'verified'
      then coalesce(u.social_links, '[]'::jsonb)
      else '[]'::jsonb
    end
  from public.photos p
  join public.users u on u.id = p.user_id
  where p.short_code = p_lookup
     or (
       p_lookup ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
       and p.id = p_lookup::uuid
     );
$function$;

-- The in-app verification page's half: the same gates without the privacy
-- one (a signed-in app user sees Humans Only owners too).
create or replace function public.get_photo_owner_profile(p_photo_id uuid)
returns table (
  username text,
  is_verified boolean,
  display_name text,
  identity_verified_at timestamptz,
  social_links jsonb
)
language sql
stable
security definer
set search_path to 'public'
as $function$
  select
    u.username,
    (u.verification_status = 'verified'),
    case
      when u.verification_status = 'verified'
       and u.show_identity
      then nullif(btrim(u.verified_first_name || ' ' || u.verified_last_name), '')
    end,
    case
      when u.verification_status = 'verified'
       and u.show_identity
      then u.identity_verified_at
    end,
    case
      when u.verification_status = 'verified'
      then coalesce(u.social_links, '[]'::jsonb)
      else '[]'::jsonb
    end
  from public.photos p
  join public.users u on u.id = p.user_id
  where p.id = p_photo_id;
$function$;

-- The Stripe Identity flag, split. Both start where the old one was (`all`).
--   identity_verification_settings   — Profile settings' Verify identity
--     button and, for an unverified user, the Identity verification row.
--   identity_verification_onboarding — the onboarding step; off ⇒ skipped
--     as though the user had tapped Skip.
-- Read by the iOS app only.
insert into public.feature_flags (key, audience)
values
  ('identity_verification_settings', 'all'),
  ('identity_verification_onboarding', 'all')
on conflict (key) do nothing;
