mod kms_signer;
mod manifest;
mod watermark;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ssm::Client as SsmClient;
use kms_signer::KmsSigner;
use lambda_http::{run, service_fn, Body, Error, Request, Response};

/// SSM parameter holding the public (not secret) leaf+CA cert chain — see
/// the checklist's cert-issuance step. Read once at cold start rather than
/// bundled into the image, specifically so this image doesn't depend on
/// something that depends on this image.
const CERT_CHAIN_PARAM: &str = "/c2pa/cert-chain";

/// The one Lambda in this project: signs JPEGs for the `sign-photo` Supabase
/// Edge Function, over a SigV4-authenticated Function URL (see
/// supabase/functions/sign-photo/index.ts), using a KMS-held key that never
/// leaves AWS. See aws-signing-lambda/README.md for provisioning.
///
/// Two routes:
/// - `POST /` — sign the body as-is as a `digitalCapture`. The original
///   route, still what builds predating server-side watermarking use, and
///   step one of the capture pipeline.
/// - `POST /watermark` — step two: the body must be a capture already
///   signed by `/`; returns it with the brand mark burned in, signed with the
///   capture as its parent ingredient.
///
/// Two calls rather than one returning both images: a Function URL response
/// is capped at 6MB (base64-encoded), which one full-resolution JPEG
/// already comes close to.
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

    enum Route {
        Capture,
        Watermark,
    }
    let route = match req.uri().path().trim_end_matches('/') {
        "" => Route::Capture,
        "/watermark" => Route::Watermark,
        other => {
            return Ok(Response::builder()
                .status(404)
                .body(Body::Text(format!("No route {other}")))?);
        }
    };

    // c2pa-rs's Builder is synchronous, and KmsSigner blocks its own
    // thread waiting on KMS — both wrong to run directly on an async task,
    // so this whole call is pushed onto Tokio's blocking thread pool.
    let signed = tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<u8>> {
        let signer = KmsSigner::new(kms_client, key_id, &cert_chain_pem)?;
        match route {
            Route::Capture => Ok(manifest::sign_capture(&image_data, &signer)?),
            Route::Watermark => manifest::sign_watermarked(&image_data, &signer),
        }
    })
    .await??;

    Ok(Response::builder()
        .status(200)
        .header("content-type", "image/jpeg")
        .body(Body::Binary(signed))?)
}
