# C2PA Signing Lambda

Rust Lambda that signs C2PA manifests server-side, using a private key that
lives entirely inside AWS KMS and never leaves it. This is the server-side
counterpart to `Verification/PhotoSigner.swift` in the iOS app
(`the-human-internet-app`), which signs on-device with a bundled dev key —
this Lambda exists specifically so a real production key never has to ship
inside a distributable app. Part of **The Human Internet** project; see the
Notion page **The Human Internet → Technical Architecture and Docs →
Server-Side C2PA Signing — AWS Setup Checklist** for the full provisioning
history and rationale behind every AWS resource this depends on.

## Status (as of 2026-08-13)

Deployed and verified end-to-end against a real KMS key: invoked the Lambda
directly with a test JPEG, ran the signed output through `c2patool`, got
`validation_state: Valid` with `claimSignature.validated` and
`assertion.dataHash.match` both passing. The one expected failure is
`signingCredential.untrusted` — correct, since the cert chain is a
self-issued dev CA until the C2PA Conformance Program is complete (separate,
non-technical process — see the app repo's `CLAUDE.md` Known Gap #1).

## Architecture

- `src/main.rs` — `lambda_http` entry point. Reads `KMS_KEY_ID` from the
  environment and the leaf+CA cert chain from SSM Parameter Store
  (`/c2pa/cert-chain`) once at cold start — deliberately **not** bundled
  into the image, so the image can build independently of the cert
  (bundling would make it depend on something that depends on it).
- `src/kms_signer.rs` — implements c2pa-rs's `Signer` trait against
  `aws-sdk-kms`'s `Sign` operation instead of holding a PEM key. KMS
  returns ASN.1 DER-encoded ECDSA signatures; COSE ES256 needs fixed-width
  raw `r||s`. `p256::ecdsa::Signature::from_der(...).to_bytes()` does the
  conversion — confirmed correct against a real signature (see Status).
- **Three routes** (`Route` in `src/main.rs`):
  - `POST /pipeline` is the capture pipeline in **one call**: it downloads
    the raw capture once and **decodes it once**, signs it as a
    `digitalCapture` (the original) with a thumbnail made from those pixels
    (`manifest::sign_original`), then watermarks the same pixels and signs
    the result with the signed capture as its `parentOf` ingredient (the
    photo), exactly as `/watermark` does — minus `/watermark`'s `Reader`
    re-check of its input and its second decode, since these are bytes the
    same invocation signed a moment earlier
    (`manifest::watermark_signed_capture`). Reusing the raw capture's pixels
    for the photo rests on signing changing no pixel: c2pa only inserts APP11
    segments, so the original decodes to exactly the raw capture's pixels,
    orientation and ICC profile included
    (`the_signed_capture_decodes_to_the_raw_captures_pixels`). The original
    is uploaded while the photo is being made. Only over the Storage hand-off (two photos
    never fit one Function URL response); without it, `400`. This is what
    `sign-photo` calls.
  - `POST /capture` signs the body as-is as a `digitalCapture` — all a
    build predating server-side watermarking needs, and step one of the
    two-call pipeline;
  - `POST /watermark` takes a capture *already signed by `/capture`*,
    burns the brand mark in and signs the result with that signed capture
    as its `parentOf` ingredient (`c2pa.opened` → `c2pa.placed`, the
    brand-mark PNG as a `componentOf` ingredient). `sign-photo` falls back
    to `/capture` then `/watermark` when `/pipeline` 404s, i.e. against a
    Lambda deployed before it; see the repo root `CLAUDE.md`.
  - **Any other path 404s** — which is how `sign-photo` tells a Lambda
    without `/pipeline` apart, so keep `Route::for_path` answering 404 for
    unknown paths before anything looks at the body. `/capture` stays
    regardless: it is the only route a request without the pipeline header
    uses. Keep `/watermark` until the `sign-photo` that calls `/pipeline`
    has been live for a while; after that only a rollback of `sign-photo`
    would need it.
  - **`POST /` is a temporary alias for `/capture`.** The `sign-photo`
    deployed before routing existed POSTs to the Function URL's root, and
    this Lambda may be deployed first. Remove the alias (`Route::for_path`)
    once the `sign-photo` that calls `/capture` is live — nothing else calls
    this Lambda.
  - **Every success names the route that ran** in `x-signing-route`.
    `sign-photo` refuses a `/watermark` response without
    `x-signing-route: watermark`, and a `/pipeline` one without
    `x-signing-route: pipeline`: the Lambda before routing ignored the path
    and signed everything as a capture, which would have returned an
    *unwatermarked* photo for the app to publish.
- `src/manifest.rs` — both manifests, hand-written JSON rather than typed
  assertion structs, because c2pa-rs's v2 actions assertion wants camelCase
  `digitalSourceType` and the typed builders don't reliably produce that.
  `/watermark` refuses input with no C2PA manifest, so the ingredient is
  always a signed capture.
- `src/handoff.rs` — the **Storage hand-off**. With `x-signing-transport:
  storage-v1` the body is `{source_url, dest_url}`: signed Supabase Storage
  links (download the input, upload the output) for two objects in the
  private `signing-handoff` bucket, instead of the photo. The Lambda
  downloads, signs as usual, uploads, and answers `{bytes, sha256}` so
  `sign-photo` can check what it fetches. `/pipeline`'s body is
  `{source_url, original_url, photo_url}` — one input, two outputs — and
  its answer `{original: {bytes, sha256}, photo: {bytes, sha256}}`. This
  exists because a Function URL caps each request and response at 6MB after
  base64 (~4.5MB of JPEG) and a detailed capture is bigger — it was a `413`
  before reaching this code.
  Links must be https on **`HANDOFF_STORAGE_HOST`** (a Lambda env var, the
  project's host); unset, the hand-off is refused and only photo-in-body
  requests work. No redirects are followed, and the source is capped at
  64MB. The Lambda holds no Supabase credentials.
  **What it can reach** is only the objects those links name, all in
  `signing-handoff`: the input (download, 5 minutes) and each output
  (upload, once — the links are made without upsert, so each can write its
  object only while it doesn't exist). It is never handed a link into
  `photo-originals`; `sign-photo` copies the original there itself, inside
  Storage. A Supabase upload link lasts 2 hours and can't be shortened,
  which is why none points at anything that outlives the call. Errors drop
  the URL (`reqwest::Error::without_url`), so no link reaches CloudWatch.
- `src/watermark.rs` — composites the brand mark, **an image:
  `assets/brand-mark.png`** (embedded with `include_bytes!`), onto the
  decoded capture: width 9% of the shorter side, height from the PNG's own
  aspect ratio, inset 3.5%, top-trailing. The PNG is the spiral
  "fingerprint" (rendered from the website's `public/brand/mark.svg`) and
  **only its alpha is used**: the mark is filled **solid black or solid
  white, whichever reads against the photo under it** — `mark_color`
  samples a 32×32 grid across the mark's box, averages Rec. 709 luma on the
  encoded values, and picks black above 0.5, white at or below. The iOS and
  Android apps implement the same rule (on-device watermarker and the
  processing overlay), so the overlay and the burned-in mark agree except
  for a box averaging right at the threshold. **EXIF orientation is applied
  first** — an iPhone stores portraits sideways and tagged — and the ICC
  profile is kept; other metadata is dropped. **The same PNG is the iOS
  app's `BrandMarkWatermark` image set and Android's
  `brand_mark_watermark`**; to change the artwork, replace it in all three
  repos (transparent background, ≥ ~600px wide) and update the dimension
  check in each repo's tests (1024×1082 today).
- `src/thumbnail.rs` — **claim thumbnails, supplied rather than generated.**
  A claim thumbnail (C2PA 2.2 §18.13) is an optional, approximate picture of
  the asset when it was signed, at most one per manifest, in any format;
  validators check its hash but never compare it with the asset's pixels. It
  is what the Content Credentials viewer pictures a manifest by, and an
  ingredient by too, through *that ingredient's own* manifest's claim
  thumbnail (§18.13.1.2). Without one the card is blank. c2pa-rs's
  `add_thumbnails` feature makes one whenever a definition has no
  `thumbnail`: it decodes the whole JPEG being signed, applies orientation,
  downscales and re-encodes (~110ms per 12MP capture on an M1 core, an
  estimated ~0.5s here). So every manifest now names its own:
  - the **original** (`/pipeline`) and the **photo**: made by
    `thumbnail::from_pixels` from the upright pixels already decoded for the
    watermark, the photo's after the mark is composited;
  - a **`/capture`** signed on its own: `thumbnail::from_jpeg_scaled`
    decodes the JPEG at 1/8, 1/4 or 1/2 scale (the smallest that is still
    ≥768px on the long edge — 1/4 for a 12MP iPhone capture) with
    `jpeg-decoder`, whose IDCT can scale (image's own decoder, zune-jpeg,
    can't), then applies EXIF orientation;
  - the **brand mark**: its 512px JPEG (`watermark::Watermarked::mark_thumbnail_jpeg`),
    the one thumbnail that's cached, once per colour, since nothing else
    about the photo changes it.

  Original, photo and `/capture` match c2pa's defaults
  (`ThumbnailSettings::default()`, pinned by a test): JPEG at quality 75
  (`Medium`), 1024px long edge (768–1024 for `/capture`), upright, with the
  same `imageops::thumbnail` downscale. Two deliberate differences: nothing
  smaller is enlarged to 1024, and **the capture's ICC profile is embedded**
  (Display P3 on an iPhone, ~0.5KB) so the thumbnail shows the photo's
  colours. c2pa's has no profile, so its P3 values get read as sRGB and look
  duller. Every thumbnail is made from its own asset's pixels at signing
  time, and none is reused across photos.

  **Ingredients reference their own claim thumbnails**
  (`manifest::add_signed_ingredient`): the photo's `parentOf` ingredient
  points at the original's `c2pa.thumbnail.claim`, the `componentOf` one at
  the mark's. c2pa-rs only makes that reference itself for an ingredient
  that validates with *no* failure, and with our dev CA there is always one,
  `signingCredential.untrusted` (Gotcha 4). Until 2026-10-14 every photo
  therefore embedded freshly generated `c2pa.thumbnail.ingredient`s instead:
  the capture decoded a second time, and the transparent mark enlarged to a
  1024px PNG (~400KB per photo). The reference is now given explicitly, as a
  hashed URI read from the ingredient's own manifest.

  **Why `add_thumbnails` stays on.** With a thumbnail named, c2pa makes
  none, so leaving the feature on costs nothing. It is also the fallback in
  every case where this code has no thumbnail to give: a `/capture` JPEG
  `jpeg-decoder` can't read (CMYK, 16-bit, malformed), or an ingredient
  without a claim thumbnail to point at (a capture signed before
  2026-10-11). Turning it off would give those cases a blank card instead of
  a slower thumbnail. Leave the feature and its settings alone.
- `src/timing.rs` — **where an invocation's time goes**, as one `timing` log
  event per step with `ms`: `download`, `decode`, `draw_mark`, `encode`
  (with the `quality` it ended at and how many `attempts` `encode_within`
  needed), `thumbnail` (`asset`, `from`), `mark_thumbnail` (once per colour
  per instance), `check_input` (`/watermark`'s `Reader`), `add_ingredient`,
  `sign` (`manifest`: `capture`, `mark`, `photo` — each includes its KMS
  round trip), `upload` (`output`), and `total` (`path`, `status`). Events
  from the signing thread carry the invocation's `requestId` like the rest.
  In CloudWatch Logs Insights:

  ```text
  filter fields.message = "timing"
  | stats avg(fields.ms), pct(fields.ms, 90), count() by fields.step, fields.manifest, fields.asset
  ```

  and `filter span.requestId = "<id>"` for one invocation, step by step.
- **Tests** (`cargo test --release`): the watermark's placement, colour
  rule and orientation handling, and both manifests read back through `c2pa::Reader`
  — `Valid`, with `signingCredential.untrusted` the only failure, the
  capture's `digitalCapture` claim surviving inside the ingredient; for
  `/pipeline`, that the photo's parent ingredient carries the very manifest
  the original was signed with. Thumbnails, through both `/pipeline` and
  `/capture` + `/watermark`: the photo, the original and the mark each have
  exactly one, and the photo embeds no other; its ingredients reference the
  original's and the mark's; an orientation-6 capture gets upright ones;
  the photo's shows the mark and the original's doesn't; and the signed
  original decodes to the raw capture's exact pixels. `handoff.rs` tests pin both body shapes and
  that every link, all three for `/pipeline`, is held to the host check.
  They sign with a throwaway CA minted per run by `rcgen`; no key is committed.
- **Sizing.** `/watermark` decodes, draws and re-encodes a full-resolution
  JPEG; `/pipeline` does that and signs the capture in the same
  invocation, so its duration is roughly `/capture`'s plus `/watermark`'s
  minus one download and one upload. At the current 768MB / 30s, check a
  real 12MP capture's duration in CloudWatch after deploying; raising to
  ~1536MB (Lambda CPU scales with memory) is the likely fix if it's tight.
  The `timing` logs (`src/timing.rs`) say which step to look at first. On a
  synthetic 4.5MB 12MP capture on an M1 core, the full-resolution `encode`
  dominated `/pipeline` once thumbnails stopped decoding: ~150ms per
  attempt, three attempts for a noise-heavy image that overshoots the 4MB
  cap at 95 and 90.

## Building

Needs a real Rust toolchain (`rustup`, not whatever ships with the OS) and
Docker for the container image — this is a **Lambda container image**, not
a zip, because it bundles the native C2PA library and its dependencies.

```bash
cargo build --release   # sanity check before containerizing
cargo clippy --release
docker build -t human-internet-signing-lambda:latest .
```

**The Docker build needs \~8GB of memory available to the builder.** The
release profile has `lto = true` (fat LTO) across a heavy dependency tree
(`c2pa` + the full AWS SDK), and a 4GB builder OOMs silently partway
through with no image produced and no clear error — it just doesn't finish.
If building via `colima` rather than Docker Desktop:

```bash
colima start --cpu 4 --memory 8 --disk 30
```

If the resulting binary fails at Lambda cold start with a glibc mismatch
(building on `rust:1-bookworm`, running on `provided:al2023`), use
`cargo lambda build --release --arm64` instead — see the Dockerfile's
comment.

## Deploying

Merging to `main` does **not** deploy the Lambda (only the Edge Functions
have a workflow). Deploy by hand, from an up-to-date `main`. The function
lives in **`us-east-2`**, account `141218266378`; the `signing-admin` SSO
profile has the rights (`aws sso login --profile signing-admin`).

```bash
export AWS_PROFILE=signing-admin AWS_REGION=us-east-2
REPO=141218266378.dkr.ecr.us-east-2.amazonaws.com/human-internet-signing-lambda
TAG=$(git rev-parse --short HEAD)

# Note the current image first — it is the rollback.
aws lambda get-function --function-name c2pa-signer --query Code.ResolvedImageUri

docker build -t $REPO:$TAG .   # arm64; see Building
aws ecr get-login-password | docker login --username AWS --password-stdin ${REPO%%/*}
docker push $REPO:$TAG
DIGEST=$(aws ecr describe-images --repository-name human-internet-signing-lambda \
  --image-ids imageTag=$TAG --query 'imageDetails[0].imageDigest' --output text)
aws lambda update-function-code --function-name c2pa-signer --image-uri $REPO@$DIGEST
aws lambda wait function-updated-v2 --function-name c2pa-signer
```

Point the function at a **digest**, not a tag, so what's running is exactly
what was built and the previous digest is a one-line rollback
(`update-function-code --image-uri $REPO@<old digest>`). Then smoke-test
`/capture` → `/watermark` as below and check both the manifest and the
mark. `/pipeline` can only be exercised through `sign-photo` (see Testing
below): once the `sign-photo` that calls it is deployed too, take one photo
through the app with `server_side_watermark` on — `sign-photo` should log
"Kept the signed capture" and never "has no /pipeline route yet" — and
check the photo's manifest, its mark, and its object in `photo-originals`.
Deploy history: 2026-09-25 `sha256:d572c32…` (server-side
watermark); 2026-10-10 `sha256:6c22a64…` (fingerprint mark, adaptive
black/white); 2026-10-11 `sha256:276cf97…` (ingredient thumbnails, `c2pa.placed`). Rollback from that one: `sha256:ad52a1f…`. 2026-10-11 `sha256:eb7a099…` (mark ingredient as drawn, JPEG thumbnail); rollback `sha256:276cf97…`. 2026-10-11 `sha256:ac3c4a6…` (ECR tag `2363eab`, the third that day; deployed but not recorded here at the time). 2026-10-14 `sha256:aafdb44…` (`35385c9`, the `/pipeline` route); rollback `sha256:ac3c4a6…`.

**Build straight to `$REPO:$TAG`, never via a `latest` tag.** A failed build
produces no image but leaves an old `latest` in place, and on 2026-10-11 a
build that died with `no space left on device` (the log's last lines don't
make the failure obvious) was followed by tagging and pushing that old
`latest` — so ECR tag `2363eab` points at the previous image, not that
commit. Built directly, a failed build leaves no `$REPO:$TAG` and the push
fails loudly instead. Check the build actually finished before pushing.

### Clean up after every deploy

The Docker VM (`colima`, see Building) has a fixed **30GB** disk, separate
from the Mac's, and nothing ever deletes old build output: every build
leaves its multi-GB Rust build stage behind as untagged images, and a
failed build keeps its half-finished container (~2GB of Rust build files
each). On 2026-10-11 that reached 30GB — 18 stale images plus three
failed-build containers up to 8 weeks old — and the build failed.

Run this after the smoke test passes:

```bash
# Every local build of this Lambda: once pushed, ECR holds its own copy.
docker images $REPO -q | sort -u | xargs docker rmi -f
docker images human-internet-signing-lambda -q | sort -u | xargs docker rmi -f   # pre-2026-10-11 local tag
# Untagged images, stopped containers, dangling build cache.
docker system prune -f
docker system df   # should be a few GB
```

Local Docker is only a build workspace, so this keeps nothing. Rollback
is `update-function-code` to an old digest, which Lambda pulls from ECR,
so it works with an empty local Docker. Nothing here touches ECR, which
keeps every image pushed to it (no lifecycle rule yet). The base images
(`rust:1-bookworm`, `provided:al2023`) stay, since they're tagged. Pruning
costs the next build nothing: this Dockerfile doesn't reuse Docker's
cache between runs anyway. Don't fix a full disk by growing `--disk`;
that only postpones it.

## Gotchas already hit and fixed here

1. **`lambda_http::Body` is `#[non_exhaustive]`** in the pinned
   `lambda_http` version — a three-arm match (`Binary`/`Text`/`Empty`)
   fails to compile without a wildcard arm.
2. **`c2pa::Builder::from_json` and `::new` are both deprecated** in
   `c2pa 0.90.15`. Use `Builder::default().with_definition(json)`.
3. **`.gitignore` must have a `target/` entry from the start.** An early
   `cargo build --release` without one dropped \~1.3GB of build artifacts
   into a parent repo's working tree, unignored. This directory now has
   its own `.gitignore` for exactly this reason.
4. **c2pa-rs won't point an ingredient at an untrusted manifest's claim
   thumbnail.** `Ingredient::update_validation_status` only references the
   ingredient's claim thumbnail when its active manifest has *no* failure,
   and `signingCredential.untrusted` counts. Our dev CA isn't on the trust
   list, so c2pa silently decoded every ingredient and embedded a new
   thumbnail instead. Nothing looked wrong: the reader still reported
   `Valid` and an ingredient thumbnail. It only showed in the assertion
   list (`c2pa.thumbnail.ingredient`). `manifest::add_signed_ingredient`
   names the reference explicitly. Once the certificate is trusted c2pa
   would make the same reference itself, and the explicit one stays
   correct.

## AWS resources this depends on (us-east-2, account `141218266378`)

- KMS key `10f3251b-a2a5-4685-816b-5f909c7124ad` (`ECC_NIST_P256`,
  `SIGN_VERIFY`) — key policy grants `kms:Sign` to this Lambda's execution
  role only, no standing human access
- SSM parameter `/c2pa/cert-chain` — public leaf+CA chain, not secret
- IAM role `c2pa-signer-lambda-role` — inline policy `SignAndReadCertChain`
  (`kms:Sign` scoped to the key above, `ssm:GetParameter` scoped to the
  cert-chain parameter) plus the managed `AWSLambdaBasicExecutionRole`
- Lambda function `c2pa-signer` — arm64, 768MB, 30s timeout (raised from 10s for the Storage hand-off's download and upload), env `KMS_KEY_ID` and `HANDOFF_STORAGE_HOST`, image from ECR
  repo `human-internet-signing-lambda`
- Function URL (`AWS_IAM` auth) — invoked by IAM user `c2pa-signer-invoker`
  (scoped to `lambda:InvokeFunctionUrl` on this function only; its access
  key lives in the app repo's Supabase project secrets, never here)
- Reserved concurrency is set to **5** (`aws lambda put-function-concurrency
  --function-name c2pa-signer --reserved-concurrent-executions 5`), capping
  abuse at 5 concurrent invocations. This was blocked until 2026-10-10 by
  the account's default new-account concurrency limit of 10 — Lambda
  requires at least 10 unreserved concurrency to remain in the account pool,
  so no reservation was possible under that ceiling. Raised via a Service
  Quotas increase request (`L-B99A9384`, account `141218266378`,
  us-east-2) from 10 to the standard default of 1000, auto-reviewed and
  approved same-day with no manual follow-up; `aws lambda
  get-account-settings` now reports `ConcurrentExecutions: 1000`. 5 stays
  deliberately far below both that new ceiling and the downstream limits
  that would otherwise throttle under real concurrency: the KMS key's
  shared `Cryptographic operations (ECC & SM2)` quota is 1000 req/s
  account-wide, and this Lambda spends 3 `Sign` calls per photo (the
  capture, the brand mark, the photo — in one `/pipeline` call, or split
  1 + 2 across `/capture` and `/watermark`); SSM's `GetParameter` quota (read once per
  cold start, for the cert chain) is only 40 req/s, so an uncapped burst of
  concurrent cold starts would throttle there first. If real traffic ever
  needs to grow past 5, raise this deliberately rather than removing the
  reservation.

## Testing without going through the Function URL

`aws lambda invoke` can hit the function directly with a Function-URL-shaped
event payload, bypassing SigV4 entirely for a quick smoke test. For
`/watermark`, set both paths to `/watermark` and send the *output* of a
`/capture` call — a raw JPEG is refused as not a signed capture.
`/pipeline` can't be tested this way: it only takes Storage links, so test
it through `sign-photo` (see Deploying).

```json
{
  "version": "2.0",
  "rawPath": "/capture",
  "requestContext": { "http": { "method": "POST", "path": "/capture" } },
  "body": "<base64-encoded JPEG>",
  "isBase64Encoded": true
}
```

```bash
aws lambda invoke --function-name c2pa-signer \
  --payload file://event.json --cli-binary-format raw-in-base64-out \
  response.json
```

Then verify the *actual* signature, not just that it returned 200 —
`cargo install c2patool --locked` and check `validation_state: Valid` plus
`claimSignature.validated` specifically. A malformed DER→raw conversion
would still let `Builder::sign()` succeed; it only shows up as an
invalid signature at verification time.
