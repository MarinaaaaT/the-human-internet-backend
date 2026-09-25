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
/// Two routes (see `Route`):
/// - `POST /capture` — sign the body as-is as a `digitalCapture`. Step one
///   of the capture pipeline, and all a request from a build predating
///   server-side watermarking ever needs.
/// - `POST /watermark` — step two: the body must be a capture already
///   signed by `/capture`; returns it with the brand mark burned in, signed
///   with the capture as its parent ingredient.
///
/// Every success names the route that actually ran in `x-signing-route`, so
/// `sign-photo` can refuse a `/watermark` answered by a Lambda that predates
/// routing (it ignored the path and signed everything as a capture — which
/// for `/watermark` would hand back an unwatermarked photo).
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

    let Some(route) = Route::for_path(req.uri().path()) else {
        return Ok(Response::builder()
            .status(404)
            .body(Body::Text(format!("No route {}", req.uri().path())))?);
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
        .header(ROUTE_HEADER, route.name())
        .body(Body::Binary(signed))?)
}

/// Response header naming the route that ran. Mirrored in `sign-photo`.
const ROUTE_HEADER: &str = "x-signing-route";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Capture,
    Watermark,
}

impl Route {
    fn for_path(path: &str) -> Option<Route> {
        match path.trim_end_matches('/') {
            "/capture" => Some(Route::Capture),
            // Temporary alias: the `sign-photo` deployed before routing
            // existed POSTs to the Function URL's root, and this Lambda can
            // be deployed before the `sign-photo` that calls `/capture`.
            // Remove once that `sign-photo` is live — nothing else calls it.
            "" => Some(Route::Capture),
            "/watermark" => Some(Route::Watermark),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Route::Capture => "capture",
            Route::Watermark => "watermark",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Route;

    #[test]
    fn routes_resolve_by_path() {
        assert_eq!(Route::for_path("/capture"), Some(Route::Capture));
        assert_eq!(Route::for_path("/capture/"), Some(Route::Capture));
        assert_eq!(Route::for_path("/watermark"), Some(Route::Watermark));
        assert_eq!(Route::for_path("/"), Some(Route::Capture), "legacy root alias");
        assert_eq!(Route::for_path(""), Some(Route::Capture), "legacy root alias");
        assert_eq!(Route::for_path("/sign"), None);
        assert_eq!(Route::for_path("/watermark/extra"), None);
    }

    #[test]
    fn route_header_names_what_ran() {
        assert_eq!(Route::Capture.name(), "capture");
        assert_eq!(Route::Watermark.name(), "watermark");
    }
}
