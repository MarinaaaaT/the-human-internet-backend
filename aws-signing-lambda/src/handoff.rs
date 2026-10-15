//! The Storage hand-off: how `sign-photo` passes photos to this Lambda
//! without putting them in the request.
//!
//! A Function URL caps a request **and** a response at 6MB, measured after
//! base64 — about 4.5MB of JPEG. A detailed 12MP capture is bigger than that,
//! and was refused before it ever reached this code (`413`, on every retry).
//! So instead of the photo, `sign-photo` sends two short-lived Supabase
//! Storage links for one private, service-role-only bucket
//! (`signing-handoff`):
//!
//! - `source_url`: a signed *download* link for exactly the input object;
//! - `dest_url`: a signed *upload* link for exactly the output object.
//!
//! This Lambda downloads the input, does the same signing as ever, uploads
//! the result, and answers with its size and SHA-256 so `sign-photo` can check
//! it fetched exactly what was written. It holds no Supabase credentials: the
//! links are the only access it ever gets, to two objects, for minutes.
//!
//! `/pipeline` is the same with one input and **two** outputs
//! ([`PipelineRequest`]): the signed capture (`original_url`) and the
//! watermarked photo (`photo_url`), each an upload link for its own
//! hand-off object, described in the answer by size and SHA-256 like any
//! other output. Still no link to anything outside `signing-handoff`:
//! `sign-photo` copies the original into `photo-originals` itself.
//!
//! Opt-in per request with `x-signing-transport: storage-v1`; without it the
//! body is the photo, as before, so this Lambda can be deployed ahead of the
//! `sign-photo` that uses the hand-off. `/pipeline` only exists with it —
//! two photos would never fit one Function URL response.
//!
//! Errors never include a link: reqwest puts the request URL, token and all,
//! in its error messages, and these end up in CloudWatch.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Duration;

/// Request header that selects this transport, echoed on the response.
/// Mirrored in `supabase/functions/sign-photo/index.ts`.
pub const TRANSPORT_HEADER: &str = "x-signing-transport";
pub const STORAGE_TRANSPORT: &str = "storage-v1";

/// The only host a link may point at: the Supabase project's own, e.g.
/// `xpjkgngifffzdaikjakw.supabase.co`. Set on the Lambda; unset ⇒ the hand-off
/// is refused outright (the photo-in-body transport still works). Without it
/// this would fetch any URL it was handed.
pub const ALLOWED_HOST_ENV: &str = "HANDOFF_STORAGE_HOST";

/// Larger than any capture (a 48MP JPEG is ~25MB), small enough that a bad
/// link can't make the function buffer something absurd.
const MAX_SOURCE_BYTES: u64 = 64 * 1024 * 1024;

/// Per transfer. Both are AWS → Supabase over the public internet, a few MB.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Deserialize)]
pub struct HandoffRequest {
    pub source_url: String,
    pub dest_url: String,
}

#[derive(Debug, Serialize, PartialEq)]
pub struct HandoffResponse {
    pub bytes: usize,
    pub sha256: String,
}

/// `/pipeline`'s body: the raw capture to download, and an upload link for
/// each of its two outputs.
#[derive(Debug, Deserialize)]
pub struct PipelineRequest {
    pub source_url: String,
    /// For the signed capture — the photo's parent ingredient, which
    /// `sign-photo` keeps in `photo-originals`.
    pub original_url: String,
    /// For the watermarked photo, which `sign-photo` hands back to the app.
    pub photo_url: String,
}

/// `/pipeline`'s answer: each output described as a single-output route
/// describes its one.
#[derive(Debug, Serialize, PartialEq)]
pub struct PipelineResponse {
    pub original: HandoffResponse,
    pub photo: HandoffResponse,
}

impl HandoffRequest {
    /// Parses the JSON body and checks both links point at `allowed_host`
    /// over HTTPS, and nowhere else.
    pub fn parse(body: &[u8], allowed_host: Option<&str>) -> Result<HandoffRequest> {
        let allowed_host = require_allowed_host(allowed_host)?;
        let request: HandoffRequest =
            serde_json::from_slice(body).context("hand-off body is not {source_url, dest_url}")?;
        check_url(&request.source_url, allowed_host).context("source_url")?;
        check_url(&request.dest_url, allowed_host).context("dest_url")?;
        Ok(request)
    }
}

impl PipelineRequest {
    /// Parses the JSON body and checks all three links point at
    /// `allowed_host` over HTTPS, and nowhere else.
    pub fn parse(body: &[u8], allowed_host: Option<&str>) -> Result<PipelineRequest> {
        let allowed_host = require_allowed_host(allowed_host)?;
        let request: PipelineRequest = serde_json::from_slice(body)
            .context("pipeline body is not {source_url, original_url, photo_url}")?;
        check_url(&request.source_url, allowed_host).context("source_url")?;
        check_url(&request.original_url, allowed_host).context("original_url")?;
        check_url(&request.photo_url, allowed_host).context("photo_url")?;
        Ok(request)
    }
}

fn require_allowed_host(allowed_host: Option<&str>) -> Result<&str> {
    allowed_host
        .filter(|h| !h.is_empty())
        .with_context(|| format!("{ALLOWED_HOST_ENV} is not set, so the storage hand-off is disabled"))
}

fn check_url(raw: &str, allowed_host: &str) -> Result<()> {
    let url = reqwest::Url::parse(raw).context("not a URL")?;
    if url.scheme() != "https" {
        bail!("must be https");
    }
    if url.host_str() != Some(allowed_host) || url.port().is_some() {
        bail!("must point at {allowed_host}");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("must not carry credentials");
    }
    Ok(())
}

pub fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .timeout(TRANSFER_TIMEOUT)
        // A signed link is a direct object URL; a redirect would be a link
        // pointing somewhere the host check never saw.
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}

/// Downloads the input object.
pub async fn fetch_source(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("downloading the source")?;
    let status = response.status();
    if !status.is_success() {
        bail!("source download returned {status}");
    }
    if response.content_length().is_some_and(|n| n > MAX_SOURCE_BYTES) {
        bail!("source is larger than {MAX_SOURCE_BYTES} bytes");
    }
    let bytes = response
        .bytes()
        .await
        .map_err(reqwest::Error::without_url)
        .context("reading the source")?;
    if bytes.len() as u64 > MAX_SOURCE_BYTES {
        bail!("source is larger than {MAX_SOURCE_BYTES} bytes");
    }
    Ok(bytes.to_vec())
}

/// Uploads the signed result to the output object, and describes it for the
/// response.
pub async fn store_result(client: &reqwest::Client, url: &str, signed: Vec<u8>) -> Result<HandoffResponse> {
    let described = describe(&signed);
    let response = client
        .put(url)
        .header("content-type", "image/jpeg")
        .body(signed)
        .send()
        .await
        .map_err(reqwest::Error::without_url)
        .context("uploading the result")?;
    let status = response.status();
    if !status.is_success() {
        let detail = response.text().await.unwrap_or_default();
        bail!("result upload returned {status}: {detail}");
    }
    Ok(described)
}

pub fn describe(bytes: &[u8]) -> HandoffResponse {
    HandoffResponse {
        bytes: bytes.len(),
        sha256: Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "xpjkgngifffzdaikjakw.supabase.co";

    fn body(source: &str, dest: &str) -> Vec<u8> {
        serde_json::json!({ "source_url": source, "dest_url": dest }).to_string().into_bytes()
    }

    fn ok_source() -> String {
        format!("https://{HOST}/storage/v1/object/sign/signing-handoff/a/in.jpg?token=t")
    }

    fn ok_dest() -> String {
        format!("https://{HOST}/storage/v1/object/upload/sign/signing-handoff/a/out.jpg?token=t")
    }

    #[test]
    fn accepts_two_https_links_on_the_project_host() {
        let request = HandoffRequest::parse(&body(&ok_source(), &ok_dest()), Some(HOST)).unwrap();
        assert!(request.source_url.contains("/object/sign/"));
        assert!(request.dest_url.contains("/object/upload/sign/"));
    }

    #[test]
    fn is_disabled_until_the_allowed_host_is_configured() {
        assert!(HandoffRequest::parse(&body(&ok_source(), &ok_dest()), None).is_err());
        assert!(HandoffRequest::parse(&body(&ok_source(), &ok_dest()), Some("")).is_err());
    }

    /// The Lambda must never be made to fetch, or write to, anywhere else.
    #[test]
    fn refuses_links_anywhere_but_the_project_over_https() {
        for bad in [
            format!("http://{HOST}/storage/v1/object/sign/x?token=t"),
            "https://evil.example/storage/v1/object/sign/x".to_string(),
            format!("https://{HOST}.evil.example/x"),
            format!("https://evil.example@{HOST}.attacker.net/x"),
            format!("https://user:pass@{HOST}/x"),
            format!("https://{HOST}:8443/x"),
            "https://169.254.169.254/latest/meta-data/".to_string(),
            "file:///etc/passwd".to_string(),
            "not a url".to_string(),
        ] {
            assert!(HandoffRequest::parse(&body(&bad, &ok_dest()), Some(HOST)).is_err(), "source {bad}");
            assert!(HandoffRequest::parse(&body(&ok_source(), &bad), Some(HOST)).is_err(), "dest {bad}");
        }
    }

    #[test]
    fn refuses_a_body_that_is_not_the_handoff_json() {
        assert!(HandoffRequest::parse(b"\xff\xd8\xff not json", Some(HOST)).is_err());
        assert!(HandoffRequest::parse(br#"{"source_url": "x"}"#, Some(HOST)).is_err());
    }

    fn pipeline_body(source: &str, original: &str, photo: &str) -> Vec<u8> {
        serde_json::json!({ "source_url": source, "original_url": original, "photo_url": photo })
            .to_string()
            .into_bytes()
    }

    fn ok_original() -> String {
        format!("https://{HOST}/storage/v1/object/upload/sign/signing-handoff/a/original.jpg?token=t")
    }

    #[test]
    fn pipeline_accepts_three_https_links_on_the_project_host() {
        let request =
            PipelineRequest::parse(&pipeline_body(&ok_source(), &ok_original(), &ok_dest()), Some(HOST)).unwrap();
        assert_eq!(request.source_url, ok_source());
        assert_eq!(request.original_url, ok_original());
        assert_eq!(request.photo_url, ok_dest());
    }

    #[test]
    fn pipeline_is_disabled_until_the_allowed_host_is_configured() {
        let body = pipeline_body(&ok_source(), &ok_original(), &ok_dest());
        assert!(PipelineRequest::parse(&body, None).is_err());
        assert!(PipelineRequest::parse(&body, Some("")).is_err());
    }

    /// Each of the three links is checked, not just the first two.
    #[test]
    fn pipeline_refuses_any_link_anywhere_but_the_project_over_https() {
        for bad in [
            format!("http://{HOST}/storage/v1/object/upload/sign/x?token=t"),
            "https://evil.example/storage/v1/object/upload/sign/x".to_string(),
            format!("https://{HOST}.evil.example/x"),
            format!("https://user:pass@{HOST}/x"),
            format!("https://{HOST}:8443/x"),
            "https://169.254.169.254/latest/meta-data/".to_string(),
            "not a url".to_string(),
        ] {
            for (body, which) in [
                (pipeline_body(&bad, &ok_original(), &ok_dest()), "source"),
                (pipeline_body(&ok_source(), &bad, &ok_dest()), "original"),
                (pipeline_body(&ok_source(), &ok_original(), &bad), "photo"),
            ] {
                let err = PipelineRequest::parse(&body, Some(HOST)).unwrap_err();
                assert!(format!("{err:#}").contains(&format!("{which}_url")), "{which} {bad}: {err:#}");
            }
        }
    }

    /// A single-output body sent to `/pipeline`, or a pipeline body sent to
    /// `/capture` or `/watermark`, is refused rather than half-read.
    #[test]
    fn the_two_body_shapes_are_not_interchangeable() {
        let single = body(&ok_source(), &ok_dest());
        let pipeline = pipeline_body(&ok_source(), &ok_original(), &ok_dest());
        assert!(PipelineRequest::parse(&single, Some(HOST)).is_err());
        assert!(HandoffRequest::parse(&pipeline, Some(HOST)).is_err());
        assert!(PipelineRequest::parse(b"\xff\xd8\xff not json", Some(HOST)).is_err());
    }

    #[test]
    fn pipeline_answer_describes_both_outputs() {
        let answer = PipelineResponse { original: describe(b"abc"), photo: describe(b"") };
        assert_eq!(
            serde_json::to_value(&answer).unwrap(),
            serde_json::json!({
                "original": {
                    "bytes": 3,
                    "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                },
                "photo": {
                    "bytes": 0,
                    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                },
            })
        );
    }

    #[test]
    fn describes_the_result_by_size_and_sha256() {
        assert_eq!(
            describe(b"abc"),
            HandoffResponse {
                bytes: 3,
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            }
        );
    }
}
