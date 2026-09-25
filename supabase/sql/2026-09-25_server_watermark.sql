-- Server-side watermarking: keep each signed capture (the ingredient of the
-- shared photo) and say where it is.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before deploying the sign-photo that writes to the bucket.
-- Purely additive.

-- Private bucket for signed captures, at `{user_id}/{photo_id}.jpg` like
-- `photos`. Written only by `sign-photo` with the service role — there is no
-- INSERT/UPDATE policy, so no client can plant or replace an "original". Its
-- owner can read it (photo history, later) and delete it (deleting the
-- photo). Nobody else can see it: unlike `photos`, there is no
-- any-authenticated-user or anon read policy.
insert into storage.buckets (id, name, public)
values ('photo-originals', 'photo-originals', false)
on conflict (id) do nothing;

create policy "Owners can view their own photo originals"
  on storage.objects for select to authenticated
  using (
    bucket_id = 'photo-originals'
    and ((storage.foldername(name))[1])::uuid = auth.uid()
  );

create policy "Owners can delete their own photo originals"
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'photo-originals'
    and ((storage.foldername(name))[1])::uuid = auth.uid()
  );

-- Where a photo's signed capture lives in `photo-originals`; NULL for photos
-- from builds that watermarked on device (they have no separate original).
-- Written by the app with the rest of the row. Nullable and unread by any
-- RPC, so older builds that never send it are unaffected.
alter table public.photos add column original_storage_path text;

-- On ⇒ the app sends the raw capture through sign-photo's capture pipeline
-- (server watermarks + signs with the capture as ingredient) instead of
-- watermarking on device. Read by the app only. Starts `off`: turn it on only
-- after the Lambda's `/watermark` route and the new sign-photo are deployed
-- — the app refuses to upload a response that doesn't confirm the pipeline,
-- so flipping it early stalls uploads rather than shipping unwatermarked
-- photos, but it does stall them.
insert into public.feature_flags (key, audience)
values ('server_side_watermark', 'off')
on conflict (key) do nothing;
