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
- `src/manifest.rs` — the manifest JSON, hand-written rather than built
  from typed assertion structs, because c2pa-rs's v2 actions assertion
  wants camelCase `digitalSourceType` and the typed builders don't reliably
  produce that (same issue `PhotoSigner.swift` hit; keep the two manifest
  shapes in sync, there's no shared source between the Swift and Rust
  signers).

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

## AWS resources this depends on (us-east-2, account `141218266378`)

- KMS key `10f3251b-a2a5-4685-816b-5f909c7124ad` (`ECC_NIST_P256`,
  `SIGN_VERIFY`) — key policy grants `kms:Sign` to this Lambda's execution
  role only, no standing human access
- SSM parameter `/c2pa/cert-chain` — public leaf+CA chain, not secret
- IAM role `c2pa-signer-lambda-role` — inline policy `SignAndReadCertChain`
  (`kms:Sign` scoped to the key above, `ssm:GetParameter` scoped to the
  cert-chain parameter) plus the managed `AWSLambdaBasicExecutionRole`
- Lambda function `c2pa-signer` — arm64, 768MB, 10s timeout, image from ECR
  repo `human-internet-signing-lambda`
- Function URL (`AWS_IAM` auth) — invoked by IAM user `c2pa-signer-invoker`
  (scoped to `lambda:InvokeFunctionUrl` on this function only; its access
  key lives in the app repo's Supabase project secrets, never here)
- Reserved concurrency is **not** set (would cap abuse at 5 concurrent
  invocations) — blocked on the AWS account's default new-account
  concurrency limit of 10, which doesn't leave room for a 5-wide
  reservation. Revisit once the account's limit is raised.

## Testing without going through the Function URL

`aws lambda invoke` can hit the function directly with a Function-URL-shaped
event payload, bypassing SigV4 entirely for a quick smoke test:

```json
{
  "version": "2.0",
  "rawPath": "/",
  "requestContext": { "http": { "method": "POST", "path": "/" } },
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
