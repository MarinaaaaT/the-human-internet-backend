use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use aws_sdk_kms::Client as KmsClient;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use c2pa::{Error as C2paError, Result as C2paResult, Signer, SigningAlg};
use p256::ecdsa::Signature as P256Signature;
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;

/// Implements c2pa's `Signer` trait against an AWS KMS asymmetric key
/// instead of a PEM private key — the counterpart to
/// `PhotoSigner.loadSigner()` on the iOS side, except the key material
/// itself never exists outside KMS's boundary. See
/// aws-signing-lambda/README.md for how the key + cert chain are
/// provisioned.
pub struct KmsSigner {
    client: KmsClient,
    key_id: String,
    /// Tokio's documented way to call async code (the KMS SDK) from a sync
    /// trait method: capture the runtime `Handle` up front, then
    /// `block_on` it. Only valid because every call site runs this signer
    /// from inside `spawn_blocking`, never directly on an async task — see
    /// main.rs.
    handle: Handle,
    cert_chain_der: Vec<Vec<u8>>,
}

impl KmsSigner {
    pub fn new(client: KmsClient, key_id: String, cert_chain_pem: &str) -> anyhow::Result<Self> {
        Ok(Self {
            client,
            key_id,
            handle: Handle::current(),
            cert_chain_der: pem_chain_to_der(cert_chain_pem)?,
        })
    }
}

impl Signer for KmsSigner {
    fn sign(&self, data: &[u8]) -> C2paResult<Vec<u8>> {
        // c2pa-rs calls this with the exact bytes that need an ES256
        // signature over them. We hash locally and hand KMS only the
        // digest (MessageType::Digest) rather than the full claim bytes —
        // narrower request, and the digest is all KMS needs for
        // ECDSA_SHA_256.
        let digest = Sha256::digest(data);

        let der_signature = self
            .handle
            .block_on(
                self.client
                    .sign()
                    .key_id(&self.key_id)
                    .message(Blob::new(digest.to_vec()))
                    .message_type(MessageType::Digest)
                    .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
                    .send(),
            )
            .map_err(|e| C2paError::OtherError(Box::new(e)))?
            .signature
            .ok_or_else(|| C2paError::OtherError("KMS returned no signature".into()))?
            .into_inner();

        // KMS's ECDSA output is always ASN.1 DER (a SEQUENCE of two
        // INTEGERs); COSE ES256 needs the fixed-width raw r||s form
        // instead (RFC 8152 / RFC 7518 §3.4). This conversion is the one
        // step here with no compile-time signal if it's wrong — a mismatch
        // produces a signature that fails validation, not a build error.
        // Confirm it end-to-end against a real KMS key (read the raw
        // manifest back out, the same way PhotoSigner.swift's three
        // signing-time gotchas were caught) before trusting it.
        let raw_signature = P256Signature::from_der(&der_signature)
            .map_err(|e| C2paError::OtherError(Box::new(e)))?
            .to_bytes();

        Ok(raw_signature.to_vec())
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Es256
    }

    fn certs(&self) -> C2paResult<Vec<Vec<u8>>> {
        Ok(self.cert_chain_der.clone())
    }

    fn reserve_size(&self) -> usize {
        // Headroom for the embedded COSE_Sign1 box (cert chain + signature
        // + framing) that gets reserved before the actual signature is
        // computed. 20KB comfortably covers a short leaf+CA chain at
        // ES256's signature size; re-check against the real chain from
        // the checklist's cert-issuance step if this ever starts throwing
        // a "not enough space reserved" signing error.
        20_000
    }
}

fn pem_chain_to_der(pem_chain: &str) -> anyhow::Result<Vec<Vec<u8>>> {
    pem_chain
        .split("-----BEGIN CERTIFICATE-----")
        .skip(1)
        .map(|block| {
            let base64_body: String = block
                .split("-----END CERTIFICATE-----")
                .next()
                .unwrap_or("")
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            BASE64.decode(base64_body).map_err(anyhow::Error::from)
        })
        .collect()
}
