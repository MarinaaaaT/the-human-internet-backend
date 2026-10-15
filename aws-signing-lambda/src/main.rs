mod handoff;
mod kms_signer;
mod manifest;
#[cfg(test)]
mod test_support;
mod thumbnail;
mod timing;
mod watermark;

use aws_sdk_kms::Client as KmsClient;
use aws_sdk_ssm::Client as SsmClient;
use kms_signer::KmsSigner;
use lambda_http::{run, service_fn, Body, Error, Request, Response};
use std::time::Instant;

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
/// Three routes (see `Route`):
/// - `POST /pipeline` — the whole capture pipeline in one call: sign the raw
///   capture as a `digitalCapture` (the original), then burn the brand mark
///   into it and sign that with the original as its parent ingredient (the
///   photo). Returns both, so only with the Storage hand-off.
/// - `POST /capture` — sign the body as-is as a `digitalCapture`. Step one
///   of the two-call pipeline, and all a request from a build predating
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
/// With `x-signing-transport: storage-v1` the photos are passed as
/// short-lived Storage links rather than in the request and response,
/// because a Function URL caps both at 6MB after base64 and a detailed
/// capture is bigger. See `handoff.rs`. Without that header the body is the
/// photo, as before.
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
    let key = SigningKey { kms_client, key_id, cert_chain_pem };

    run(service_fn(move |req: Request| {
        let key = key.clone();
        async move { handle(req, key).await }
    }))
    .await
}

/// [`dispatch`], with its total duration logged — see `timing.rs` for the rest
/// of the breakdown.
async fn handle(req: Request, key: SigningKey) -> Result<Response<Body>, Error> {
    let start = Instant::now();
    let path = req.uri().path().to_owned();
    let response = dispatch(req, key).await;
    let status = response.as_ref().map_or(500, |r| r.status().as_u16());
    tracing::info!(step = "total", path, status, ms = timing::ms_since(start), "timing");
    response
}

async fn dispatch(req: Request, key: SigningKey) -> Result<Response<Body>, Error> {
    let body = match req.body() {
        Body::Binary(bytes) => bytes.clone(),
        Body::Text(text) => text.clone().into_bytes(),
        Body::Empty => Vec::new(),
        // Body is #[non_exhaustive]; only these three variants exist today.
        _ => Vec::new(),
    };

    if body.is_empty() {
        return Ok(Response::builder()
            .status(400)
            .body(Body::Text("Missing image data".into()))?);
    }

    let Some(route) = Route::for_path(req.uri().path()) else {
        return Ok(Response::builder()
            .status(404)
            .body(Body::Text(format!("No route {}", req.uri().path())))?);
    };

    let uses_storage = req
        .headers()
        .get(handoff::TRANSPORT_HEADER)
        .is_some_and(|v| v.as_bytes() == handoff::STORAGE_TRANSPORT.as_bytes());
    if route == Route::Pipeline {
        if !uses_storage {
            return Ok(Response::builder().status(400).body(Body::Text(format!(
                "/pipeline returns two photos, which only the storage hand-off can carry \
                 ({}: {})",
                handoff::TRANSPORT_HEADER,
                handoff::STORAGE_TRANSPORT
            )))?);
        }
        return pipeline(&body, key).await;
    }
    if !uses_storage {
        let signed = sign(route, body, &key).await?;
        return Ok(Response::builder()
            .status(200)
            .header("content-type", "image/jpeg")
            .header(ROUTE_HEADER, route.name())
            .body(Body::Binary(signed))?);
    }

    // The body is a pair of signed Storage links, not the photo.
    let allowed_host = std::env::var(handoff::ALLOWED_HOST_ENV).ok();
    let request = match handoff::HandoffRequest::parse(&body, allowed_host.as_deref()) {
        Ok(request) => request,
        Err(error) => return refuse_handoff(error),
    };
    let client = handoff::client()?;
    let image_data = handoff::fetch_source(&client, &request.source_url).await?;
    let signed = sign(route, image_data, &key).await?;
    let stored = handoff::store_result(&client, &request.dest_url, signed, route.name()).await?;
    handoff_answer(route, &stored)
}

/// `/pipeline`: one download, one decode, both signatures, two uploads. The
/// capture's pixels, decoded once before the original is signed, make the
/// original's thumbnail and are then watermarked into the photo. The
/// original's upload runs while the photo is being made, so of the two only
/// the photo's is on the critical path.
async fn pipeline(body: &[u8], key: SigningKey) -> Result<Response<Body>, Error> {
    let allowed_host = std::env::var(handoff::ALLOWED_HOST_ENV).ok();
    let request = match handoff::PipelineRequest::parse(body, allowed_host.as_deref()) {
        Ok(request) => request,
        Err(error) => return refuse_handoff(error),
    };
    let client = handoff::client()?;
    let raw_capture = handoff::fetch_source(&client, &request.source_url).await?;

    let (original, capture) = key.run(move |signer| manifest::sign_original(&raw_capture, signer)).await?;
    let watermarking = original.clone();
    let (original, photo) = tokio::try_join!(
        handoff::store_result(&client, &request.original_url, original, "original"),
        key.run(move |signer| manifest::watermark_signed_capture(&watermarking, capture, signer)),
    )?;
    let photo = handoff::store_result(&client, &request.photo_url, photo, "photo").await?;

    handoff_answer(Route::Pipeline, &handoff::PipelineResponse { original, photo })
}

/// A hand-off body this Lambda won't act on: a 400, logged.
fn refuse_handoff(error: anyhow::Error) -> Result<Response<Body>, Error> {
    tracing::warn!(error = %format!("{error:#}"), "refused a storage hand-off");
    Ok(Response::builder()
        .status(400)
        .body(Body::Text(format!("{error:#}")))?)
}

/// A successful hand-off: the outputs are in Storage, and the answer
/// describes them.
fn handoff_answer(route: Route, described: &impl serde::Serialize) -> Result<Response<Body>, Error> {
    Ok(Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .header(ROUTE_HEADER, route.name())
        .header(handoff::TRANSPORT_HEADER, handoff::STORAGE_TRANSPORT)
        .body(Body::Text(serde_json::to_string(described)?))?)
}

/// A single-output route's signing, whichever transport the photo came by.
async fn sign(route: Route, image_data: Vec<u8>, key: &SigningKey) -> anyhow::Result<Vec<u8>> {
    key.run(move |signer| match route {
        Route::Capture => Ok(manifest::sign_capture(&image_data, signer)?),
        Route::Watermark => manifest::sign_watermarked(&image_data, signer),
        Route::Pipeline => anyhow::bail!("/pipeline has two outputs; see `pipeline`"),
    })
    .await
}

/// What a `KmsSigner` is made from, read once at cold start.
#[derive(Clone)]
struct SigningKey {
    kms_client: KmsClient,
    key_id: String,
    cert_chain_pem: String,
}

impl SigningKey {
    /// Runs `sign` with a signer for this key, on Tokio's blocking thread
    /// pool: c2pa-rs's Builder is synchronous, and `KmsSigner` blocks its own
    /// thread waiting on KMS — both wrong to run directly on an async task.
    /// Inside the invocation's span, so what it logs carries the request id.
    async fn run<T: Send + 'static>(
        &self,
        sign: impl FnOnce(&KmsSigner) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let key = self.clone();
        let span = tracing::Span::current();
        tokio::task::spawn_blocking(move || {
            let _invocation = span.enter();
            let signer = KmsSigner::new(key.kms_client, key.key_id, &key.cert_chain_pem)?;
            sign(&signer)
        })
        .await?
    }
}

/// Response header naming the route that ran. Mirrored in `sign-photo`.
const ROUTE_HEADER: &str = "x-signing-route";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Route {
    Capture,
    Watermark,
    Pipeline,
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
            "/pipeline" => Some(Route::Pipeline),
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Route::Capture => "capture",
            Route::Watermark => "watermark",
            Route::Pipeline => "pipeline",
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
        assert_eq!(Route::for_path("/pipeline"), Some(Route::Pipeline));
        assert_eq!(Route::for_path("/pipeline/"), Some(Route::Pipeline));
        assert_eq!(Route::for_path("/"), Some(Route::Capture), "legacy root alias");
        assert_eq!(Route::for_path(""), Some(Route::Capture), "legacy root alias");
        assert_eq!(Route::for_path("/sign"), None);
        assert_eq!(Route::for_path("/watermark/extra"), None);
        assert_eq!(Route::for_path("/pipeline/extra"), None);
    }

    #[test]
    fn route_header_names_what_ran() {
        assert_eq!(Route::Capture.name(), "capture");
        assert_eq!(Route::Watermark.name(), "watermark");
        assert_eq!(Route::Pipeline.name(), "pipeline");
    }
}
