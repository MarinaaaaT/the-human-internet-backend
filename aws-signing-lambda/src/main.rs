mod kms_signer;
mod manifest;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ssm::Client as SsmClient;
use kms_signer::KmsSigner;
use lambda_http::{run, service_fn, Body, Error, Request, Response};

/// SSM parameter holding the public (not secret) leaf+CA cert chain — see
/// the checklist's cert-issuance step. Read once at cold start rather than
/// bundled into the image, specifically so this image doesn't depend on
/// something that depends on this image.
const CERT_CHAIN_PARAM: &str = "/c2pa/cert-chain";

/// The one Lambda in this project: receives a raw captured JPEG (from the
/// `sign-photo` Supabase Edge Function, over a SigV4-authenticated Function
/// URL — see supabase/functions/sign-photo/index.ts) and returns it
/// C2PA-signed, using a KMS-held key that never leaves AWS. See
/// aws-signing-lambda/README.md for provisioning.
#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt().json().init();

    let aws_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms_client = KmsClient::new(&aws_config);
    let ssm_client = SsmClient::new(&aws_config);

    let key_id = std::env::var("KMS_KEY_ID").expect("KMS_KEY_ID must be set");
    let cert_chain_pem = ssm_client
        .get_parameter()
        .name(CERT_CHAIN_PARAM)
        .send()
        .await
        .expect("failed to read cert chain from SSM")
        .parameter
        .and_then(|p| p.value)
        .expect("SSM parameter had no value");

    run(service_fn(move |req: Request| {
        let kms_client = kms_client.clone();
        let key_id = key_id.clone();
        let cert_chain_pem = cert_chain_pem.clone();
        async move { handle(req, kms_client, key_id, cert_chain_pem).await }
    }))
    .await
}

async fn handle(
    req: Request,
    kms_client: KmsClient,
    key_id: String,
    cert_chain_pem: String,
) -> Result<Response<Body>, Error> {
    let image_data = match req.body() {
        Body::Binary(bytes) => bytes.clone(),
        Body::Text(text) => text.clone().into_bytes(),
        Body::Empty => Vec::new(),
        // Body is #[non_exhaustive]; only these three variants exist today.
        _ => Vec::new(),
    };

    if image_data.is_empty() {
        return Ok(Response::builder()
            .status(400)
            .body(Body::Text("Missing image data".into()))?);
    }

    // c2pa-rs's Builder is synchronous, and KmsSigner blocks its own
    // thread waiting on KMS — both wrong to run directly on an async task,
    // so this whole call is pushed onto Tokio's blocking thread pool.
    let signed = tokio::task::spawn_blocking(move || {
        let signer = KmsSigner::new(kms_client, key_id, &cert_chain_pem)?;
        manifest::sign_jpeg(&image_data, &signer).map_err(anyhow::Error::from)
    })
    .await??;

    Ok(Response::builder()
        .status(200)
        .header("content-type", "image/jpeg")
        .body(Body::Binary(signed))?)
}
