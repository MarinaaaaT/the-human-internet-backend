# Lambda has no native Rust runtime — lambda_http/lambda_runtime implement
# the Lambda Runtime API themselves, and the binary must be named
# `bootstrap` for the `provided.al2023` base image.
#
# Building on rust:1-bookworm and running on al2023 assumes glibc
# compatibility between the two, which usually holds but isn't guaranteed.
# If this build produces a binary that fails at cold start with a glibc
# version mismatch, use `cargo lambda build --release` instead (from the
# https://www.cargo-lambda.info/ project) — it's purpose-built to cross
# compile correctly for the Lambda runtime and sidesteps this entirely.

FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM public.ecr.aws/lambda/provided:al2023
COPY --from=builder /build/target/release/human-internet-signing-lambda /var/runtime/bootstrap
WORKDIR ${LAMBDA_TASK_ROOT}
CMD ["bootstrap"]
