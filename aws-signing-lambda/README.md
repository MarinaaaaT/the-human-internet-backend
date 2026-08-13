# Server-side C2PA signing Lambda

Rust Lambda counterpart to `PhotoSigner.swift` in the iOS app: same C2PA
manifest, same ES256 algorithm, but the private key lives in AWS KMS and
never leaves it. Receives a raw JPEG over its Function URL, returns the
signed JPEG. See the Notion pages under The Human Internet → Technical
Architecture and Docs for the full request flow and the AWS setup
checklist this project fulfills.

**Not yet built or deployed against a real KMS key** — this is a
from-scratch scaffold written without a local Rust toolchain to compile
against, so treat it as a first draft, not verified working code. Before
trusting it:

- `cargo build` / `cargo clippy` locally — nothing here has been compiled.
- The DER→raw ECDSA signature conversion in `src/kms_signer.rs` is the
  step most likely to be subtly wrong — it has no compile-time signal if
  the format is off, only a manifest that fails validation. Sign a test
  image, then read the manifest back with a real verifier (or
  `PhotoSigner.readManifestJSON` in the iOS app against the same bytes)
  before considering this done.
- Whether a Function URL correctly delivers a raw `application/octet-stream`
  POST body as base64/binary to `lambda_http` is worth confirming with a
  direct `curl --data-binary` test against the deployed URL, independent of
  the Supabase Edge Function.

## Building

Two options, in order of how much they insulate you from
cross-compilation/glibc mismatches between the build environment and the
Lambda `provided.al2023` runtime:

```bash
# Preferred — purpose-built for this, handles the target correctly
cargo install cargo-lambda
cargo lambda build --release --arm64
```

```bash
# Alternative — plain Docker multi-stage build, see Dockerfile's comment
# about glibc compatibility if the resulting binary fails at cold start
docker build -t signing-lambda .
```

## Deploying

Push the built image to ECR and point the Lambda (created per the AWS
checklist) at it. Required environment variables on the Lambda:

- `KMS_KEY_ID` — the KMS key's ARN or key ID from checklist step 1.

No AWS credentials are set as env vars here — the Lambda's execution role
(scoped to `kms:Sign` on that one key, per the checklist) supplies them
via the standard AWS SDK credential chain, which `aws_config::load_defaults`
picks up automatically.

The leaf + CA cert chain (public, not secret) is **not** bundled into the
image — it's read from SSM Parameter Store (`/c2pa/cert-chain`, set by the
checklist's cert-issuance step) once at cold start. This keeps the image
buildable independently of the cert — bundling it would make this step
depend on something that depends on this step.

This means the execution role needs `ssm:GetParameter` on that parameter's
ARN in addition to `kms:Sign` on the signing key — **not yet reflected in
the Notion AWS setup checklist**, which only lists `kms:Sign` for the
execution role. Add it there when you provision the role, or update the
checklist to match.

## Project layout

- `src/main.rs` — Lambda entry point (`lambda_http`), request/response
  plumbing.
- `src/kms_signer.rs` — implements c2pa's `Signer` trait against KMS.
- `src/manifest.rs` — the C2PA manifest JSON and `Builder::sign` call.
  Deliberately kept byte-for-byte identical in shape to
  `PhotoSigner.swift`'s manifest — see its comments for why the JSON is
  hand-written rather than built from typed assertion structs.
