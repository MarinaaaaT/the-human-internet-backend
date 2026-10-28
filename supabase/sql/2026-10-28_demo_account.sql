-- The demo account: `thehumaninternet://demo` in the app.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before deploying the `demo-session` Edge Function and before
-- shipping the app build that reads `is_demo`. Additive apart from the two
-- RPCs, which gain an `is_demo` column and so must be dropped and recreated
-- (re-granting exactly what they had).

-- Marks the one shared demo account. Written only by `demo-session`, under
-- the service role, when it creates or resets that account.
--
-- It must not be client-writable, and not because it claims anything about
-- the user — it claims *less*: the verification pages print "human
-- authenticity is not guaranteed" over its photos. It matters because
-- `stripe-identity-session` auto-approves an `is_demo` caller without ever
-- reaching Stripe, so a user who could set it on their own row would get
-- `verified` for free. RLS on `users` is row-scoped, not column-scoped, so
-- the same two-trigger guard as `is_admin` applies, with the same exemptions
-- (`service_role`, and a NULL `auth.role()` — a direct privileged
-- connection, so it can still be corrected by hand). The app never sends it:
-- it isn't a `HumanUser` field, and is read as a narrow one-column query.
alter table public.users
  add column if not exists is_demo boolean not null default false;

create or replace function public.prevent_self_demo_change()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  if new.is_demo is distinct from old.is_demo
     and auth.role() is not null
     and auth.role() <> 'service_role' then
    new.is_demo := old.is_demo;
  end if;
  return new;
end;
$function$;

create or replace function public.force_is_demo_false_on_insert()
returns trigger
language plpgsql
security definer
set search_path to 'public'
as $function$
begin
  if auth.role() is not null and auth.role() <> 'service_role' then
    new.is_demo := false;
  end if;
  return new;
end;
$function$;

drop trigger if exists trg_prevent_self_demo_change on public.users;
create trigger trg_prevent_self_demo_change
  before update on public.users
  for each row execute function public.prevent_self_demo_change();

drop trigger if exists trg_force_is_demo_false_on_insert on public.users;
create trigger trg_force_is_demo_false_on_insert
  before insert on public.users
  for each row execute function public.force_is_demo_false_on_insert();

-- The signed-out verification page. Unchanged except for `is_demo`, which the
-- page uses to replace its "taken by a real human" box with the demo
-- disclaimer. Deliberately ungated by privacy: it says less about a photo,
-- never more, so even a `Humans Only` demo photo's page carries it.
drop function if exists public.get_verification_photo(text);
create function public.get_verification_photo(p_lookup text)
returns table(
  storage_path text,
  username text,
  captured_at timestamp with time zone,
  is_public boolean,
  is_verified boolean,
  display_name text,
  identity_verified_at timestamp with time zone,
  social_links jsonb,
  is_demo boolean
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
    end,
    u.is_demo
  from public.photos p
  join public.users u on u.id = p.user_id
  where p.short_code = p_lookup
     or (
       p_lookup ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
       and p.id = p_lookup::uuid
     );
$function$;

revoke all on function public.get_verification_photo(text) from public;
grant execute on function public.get_verification_photo(text) to anon, authenticated, service_role;

-- The in-app verification page. Same change, same reason.
drop function if exists public.get_photo_owner_profile(uuid);
create function public.get_photo_owner_profile(p_photo_id uuid)
returns table(
  username text,
  is_verified boolean,
  display_name text,
  identity_verified_at timestamp with time zone,
  social_links jsonb,
  is_demo boolean
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
    end,
    u.is_demo
  from public.photos p
  join public.users u on u.id = p.user_id
  where p.id = p_photo_id;
$function$;

-- Authenticated only, never anon: signed-out callers have
-- `get_verification_photo()`, and this one has no privacy gate.
revoke all on function public.get_photo_owner_profile(uuid) from public, anon;
grant execute on function public.get_photo_owner_profile(uuid) to authenticated, service_role;
