-- Reporting a photo: the app's "Report photo" on the in-app verification page.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before shipping the app build that writes it. Purely additive.
--
-- App Review guideline 1.2 asks any app showing other people's content for a
-- way to report it. Write-only from the app: a signed-in user can file a
-- report on someone else's photo and read nothing back — not even their own
-- reports, so the table can't be used to learn who reported whom. Reviewing
-- them is done by hand, from the dashboard or SQL, under a privileged role.

create table public.photo_reports (
  id uuid primary key default gen_random_uuid(),
  -- Deleting the photo removes its reports: once it's gone there's nothing
  -- left to act on, and the row would only keep who reported it.
  photo_id uuid not null references public.photos (id) on delete cascade,
  reporter_id uuid not null default auth.uid() references auth.users (id) on delete cascade,
  -- Mirrored by `PhotoReportReason` in the app's Models.swift. The app only
  -- writes this column, never reads it, so a value added here and not there
  -- costs nothing; one added there and not here fails the insert.
  reason text not null check (reason in (
    'not_real',
    'sexual',
    'violent',
    'harassment',
    'privacy',
    'other'
  )),
  created_at timestamptz not null default now(),
  -- One report per person per photo. The app treats a duplicate (23505) as
  -- already reported, so tapping Report twice can't stack reports.
  unique (photo_id, reporter_id)
);

create index photo_reports_created_at_idx on public.photo_reports (created_at desc);

alter table public.photo_reports enable row level security;

-- Insert only, as yourself, about a photo that isn't yours. No SELECT,
-- UPDATE or DELETE policy exists, so nothing else is reachable through
-- PostgREST. `photos` is readable by every authenticated user, so the
-- subquery sees the row under the caller's own RLS.
create policy "Users can report other people's photos"
  on public.photo_reports
  for insert
  to authenticated
  with check (
    reporter_id = (select auth.uid())
    and exists (
      select 1 from public.photos p
      where p.id = photo_id
        and p.user_id <> (select auth.uid())
    )
  );

grant insert on public.photo_reports to authenticated;
revoke all on public.photo_reports from anon;
