-- Reporting a photo from the website's signed-out verification page.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before deploying the website build that calls it. Builds on
-- 2026-11-01_photo_reports.sql, which must already be applied.
--
-- The website has no signed-in visitors, so a web report has no reporter.
-- It can't go through the table's INSERT policy (that's for the app, as
-- yourself), so it goes through one security-definer function instead,
-- shaped like get_verification_photo(): it answers about one photo you
-- already hold the link for, and only one whose owner is Public — a
-- Humans Only page shows a visitor nothing to report.

alter table public.photo_reports alter column reporter_id drop not null;

comment on column public.photo_reports.reporter_id is
  'Who reported it, from the app. Null for a report from the signed-out website.';

create or replace function public.report_photo(p_lookup text, p_reason text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_photo_id uuid;
begin
  -- The same lookup as get_verification_photo(): a short code, or a bare
  -- photo id for links shared before short codes existed.
  select p.id into v_photo_id
  from public.photos p
  join public.users u on u.id = p.user_id
  where u.privacy = 'Public'
    and (
      p.short_code = p_lookup
      or (
        p_lookup ~ '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
        and p.id = p_lookup::uuid
      )
    );

  -- Unknown or not Public: answer exactly as for a report that went in, so
  -- this can't be used to test whether a link exists.
  if v_photo_id is null then
    return;
  end if;

  -- Anyone can call this, as often as they like, so cap what it can write:
  -- past 20 anonymous reports on one photo in a day, more add nothing a
  -- reviewer needs and are dropped. App reports aren't counted or capped.
  if (
    select count(*) from public.photo_reports r
    where r.photo_id = v_photo_id
      and r.reporter_id is null
      and r.created_at > now() - interval '1 day'
  ) >= 20 then
    return;
  end if;

  -- An unknown reason fails the CHECK constraint and raises.
  insert into public.photo_reports (photo_id, reporter_id, reason)
  values (v_photo_id, null, p_reason);
end;
$$;

revoke all on function public.report_photo(text, text) from public;
grant execute on function public.report_photo(text, text) to anon, authenticated, service_role;
