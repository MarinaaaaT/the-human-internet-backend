-- The Storage hand-off between sign-photo and the signing Lambda.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before deploying the sign-photo that uses it. Purely additive.
--
-- A Function URL caps each request and response at 6MB after base64 (about
-- 4.5MB of JPEG), and a detailed capture is bigger — it was refused with a
-- 413 before reaching the Lambda, on every retry. So sign-photo puts each
-- photo here and hands the Lambda two short-lived signed links (download the
-- input, upload the output) instead of the bytes. See
-- aws-signing-lambda/src/handoff.rs.
--
-- Private, and deliberately **no policies**: only the service role
-- (sign-photo) can touch it, and the Lambda only through the signed links it
-- is handed — one object each, for minutes. Objects live for the length of
-- one sign-photo call, which deletes them when it's done; anything left
-- behind by a call that crashed mid-way is harmless (service-role only) and
-- can be emptied any time from the dashboard (Storage → signing-handoff) or
-- the Storage API — not with a DELETE on storage.objects, which Supabase
-- refuses.
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'signing-handoff',
  'signing-handoff',
  false,
  67108864,           -- 64MB, matching the Lambda's MAX_SOURCE_BYTES
  array['image/jpeg']
)
on conflict (id) do nothing;

