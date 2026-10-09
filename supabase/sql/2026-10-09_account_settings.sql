-- Account settings: the "Photo Fingerprint" switch.
--
-- Not a tracked migration (see CLAUDE.md → Database); the record of what to
-- apply, once, before shipping the app build that reads and writes it.
-- Purely additive.

-- On (the default) ⇒ the app burns the brand mark into each new capture
-- before it's signed. Off ⇒ the raw capture is signed and shared as-is, with
-- no visible mark. Read and written only by the app, as a narrow one-column
-- query — deliberately not part of the app's whole-row `HumanUser` upsert,
-- so builds that predate the column are unaffected. It makes no claim: the
-- C2PA manifest is the proof either way, the mark is a visible pointer to it.
alter table public.users
  add column watermark_enabled boolean not null default true;
