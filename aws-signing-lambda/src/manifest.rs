use c2pa::{Builder, Reader, Result as C2paResult, Signer};
use std::io::Cursor;
use std::time::Instant;

use crate::{timing, watermark};

/// IPTC term asserting the image came off a physical capture device.
const DIGITAL_CAPTURE_URI: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";

/// IPTC term for media a human made with digital tools — the brand mark.
const DIGITAL_CREATION_URI: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCreation";

/// Label tying the watermarked photo's `c2pa.opened` action to its parent
/// ingredient (the signed capture) inside the manifest definition.
const CAPTURE_INGREDIENT_LABEL: &str = "capture";

/// Label tying the `c2pa.placed` action to the brand-mark ingredient — the
/// mark as it was placed into the capture's pixels (colour and size).
const BRAND_MARK_INGREDIENT_LABEL: &str = "brand-mark";

/// Resource id of the thumbnail supplied in the brand mark's own manifest.
const MARK_THUMBNAIL_ID: &str = "brand-mark-thumbnail.jpg";

/// The capture's manifest: `c2pa.created` + `digitalCapture` — "a real
/// camera took this", the claim the whole product rests on.
///
/// Hand-written JSON rather than typed assertion builders: c2pa-rs's v2
/// actions assertion wants camelCase `digitalSourceType`, and the typed
/// builders don't reliably produce that (the old on-device signer in the
/// app hit the same thing).
fn capture_manifest_json() -> String {
    format!(
        r#"{{
  "claim_version": 2,
  "format": "image/jpeg",
  "title": "the-human-internet-capture.jpg",
  "claim_generator_info": [
    {{ "name": "the-human-internet" }}
  ],
  "assertions": [
    {{
      "label": "c2pa.actions.v2",
      "data": {{
        "actions": [
          {{
            "action": "c2pa.created",
            "digitalSourceType": "{DIGITAL_CAPTURE_URI}"
          }}
        ]
      }}
    }}
  ]
}}"#
    )
}

/// The shared photo's manifest: opened from the signed capture (its parent
/// ingredient), then the brand mark placed into it (a component ingredient)
/// by this Lambda.
/// The capture's own `c2pa.created`/`digitalCapture` claim travels inside
/// the ingredient, so a C2PA reader shows the whole chain.
fn watermarked_manifest_json() -> String {
    format!(
        r#"{{
  "claim_version": 2,
  "format": "image/jpeg",
  "title": "the-human-internet-photo.jpg",
  "claim_generator_info": [
    {{ "name": "the-human-internet" }}
  ],
  "assertions": [
    {{
      "label": "c2pa.actions.v2",
      "data": {{
        "actions": [
          {{
            "action": "c2pa.opened",
            "parameters": {{ "ingredientIds": ["{CAPTURE_INGREDIENT_LABEL}"] }}
          }},
          {{
            "action": "c2pa.placed",
            "parameters": {{ "ingredientIds": ["{BRAND_MARK_INGREDIENT_LABEL}"] }},
            "description": "The Human Internet brand mark burned into the top-trailing corner"
          }}
        ]
      }}
    }}
  ]
}}"#
    )
}

/// The brand mark's own manifest, so that as an ingredient it carries
/// credentials (and a claim thumbnail) of its own, like the capture does.
/// The Content Credentials viewer pictures an ingredient from its manifest's
/// claim thumbnail; a bare ingredient with only an ingredient thumbnail
/// rendered as a blank card.
fn mark_manifest_json() -> String {
    format!(
        r#"{{
  "claim_version": 2,
  "format": "image/png",
  "title": "the-human-internet-brand-mark.png",
  "claim_generator_info": [
    {{ "name": "the-human-internet" }}
  ],
  "thumbnail": {{ "format": "image/jpeg", "identifier": "{MARK_THUMBNAIL_ID}" }},
  "assertions": [
    {{
      "label": "c2pa.actions.v2",
      "data": {{
        "actions": [
          {{
            "action": "c2pa.created",
            "digitalSourceType": "{DIGITAL_CREATION_URI}"
          }}
        ]
      }}
    }}
  ]
}}"#
    )
}

/// Signs the mark as drawn (a transparent PNG) with its supplied JPEG
/// thumbnail — see [`mark_manifest_json`].
fn sign_mark(mark_png: &[u8], thumbnail_jpeg: &[u8], signer: &dyn Signer) -> C2paResult<Vec<u8>> {
    let mut builder = Builder::default().with_definition(mark_manifest_json())?;
    builder.add_resource(MARK_THUMBNAIL_ID, Cursor::new(thumbnail_jpeg))?;
    sign("mark", &mut builder, "image/png", mark_png, signer)
}

/// Signs a capture (a JPEG) as-is, as a `digitalCapture`, and returns the
/// signed JPEG bytes. The `/capture` route — step one of the two-call capture
/// pipeline, and all a build predating server-side watermarking needs — and
/// the first half of `/pipeline`.
///
/// Blocking — callers on an async runtime should run this via
/// `spawn_blocking` (see main.rs), both because c2pa-rs's Builder is
/// synchronous and because `KmsSigner::sign` itself blocks on a KMS call.
pub fn sign_capture(image_data: &[u8], signer: &dyn Signer) -> C2paResult<Vec<u8>> {
    let mut builder = Builder::default().with_definition(capture_manifest_json())?;
    sign("capture", &mut builder, "image/jpeg", image_data, signer)
}

/// Step two of the capture pipeline (`/watermark`): takes a capture
/// *already signed* by `sign_capture` and does [`watermark_signed_capture`].
///
/// Refuses input with no C2PA manifest, so the ingredient is always a signed
/// capture rather than bare pixels — this route only ever sees what
/// `sign-photo` got back from step one, but the chain is only worth anything
/// if its first link is always there. Blocking, like `sign_capture`.
pub fn sign_watermarked(signed_capture: &[u8], signer: &dyn Signer) -> anyhow::Result<Vec<u8>> {
    timing::time("check_input", || {
        Reader::default().with_stream("image/jpeg", Cursor::new(signed_capture))
    })
    .map_err(|e| anyhow::anyhow!("input is not a signed capture: {e}"))?;
    watermark_signed_capture(signed_capture, signer)
}

/// The watermark step itself: burns the brand mark into a signed capture,
/// and signs the result with the signed capture as its parent ingredient and
/// the mark as drawn (see [`watermark::Watermarked::mark_png`]), itself
/// signed, as a component ingredient. Returns the watermarked JPEG.
///
/// `/watermark` gets here through [`sign_watermarked`], which first checks
/// its input really is a signed capture. `/pipeline` calls this directly, on
/// what [`sign_capture`] returned a moment earlier in the same invocation:
/// those bytes never left this Lambda, so reading them back would prove
/// nothing. Blocking, like `sign_capture`.
pub fn watermark_signed_capture(signed_capture: &[u8], signer: &dyn Signer) -> anyhow::Result<Vec<u8>> {
    let capture = watermark::decode_capture(signed_capture)?;
    let watermark::Watermarked { jpeg: watermarked, mark_png, mark_thumbnail_jpeg } =
        watermark::watermark(capture)?;

    let mut builder = Builder::default().with_definition(watermarked_manifest_json())?;
    let start = Instant::now();
    builder.add_ingredient_from_stream(
        format!(
            r#"{{ "title": "the-human-internet-capture.jpg", "relationship": "parentOf", "label": "{CAPTURE_INGREDIENT_LABEL}" }}"#
        ),
        "image/jpeg",
        &mut Cursor::new(signed_capture),
    )?;
    tracing::info!(step = "add_ingredient", ingredient = CAPTURE_INGREDIENT_LABEL, ms = timing::ms_since(start), "timing");
    // Its own credentials carry its thumbnail; the ingredient just points
    // at that, as the capture's does.
    let signed_mark = sign_mark(&mark_png, &mark_thumbnail_jpeg, signer)?;
    let start = Instant::now();
    builder.add_ingredient_from_stream(
        format!(
            r#"{{ "title": "the-human-internet-brand-mark.png", "relationship": "componentOf", "label": "{BRAND_MARK_INGREDIENT_LABEL}" }}"#
        ),
        "image/png",
        &mut Cursor::new(signed_mark),
    )?;
    tracing::info!(step = "add_ingredient", ingredient = BRAND_MARK_INGREDIENT_LABEL, ms = timing::ms_since(start), "timing");

    Ok(sign("photo", &mut builder, "image/jpeg", &watermarked, signer)?)
}

/// `Builder::sign`, timed as `manifest`'s signing. Until claim thumbnails
/// are supplied, this includes c2pa decoding `asset` to make one.
fn sign(
    manifest: &'static str,
    builder: &mut Builder,
    format: &str,
    asset: &[u8],
    signer: &dyn Signer,
) -> C2paResult<Vec<u8>> {
    let start = Instant::now();
    let mut source = Cursor::new(asset);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(signer, format, &mut source, &mut dest)?;
    tracing::info!(step = "sign", manifest, ms = timing::ms_since(start), "timing");
    Ok(dest.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{codecs::jpeg::JpegEncoder, ExtendedColorType, ImageEncoder, Rgb, RgbImage};
    use serde_json::Value;

    /// A throwaway CA + leaf, minted per test run so no private key is ever
    /// committed. Shaped like the real dev chain: an EC P-256 leaf with
    /// digitalSignature + emailProtection, issued by a separate CA.
    fn test_signer() -> Box<dyn Signer> {
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
            KeyUsagePurpose,
        };
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.distinguished_name.push(DnType::CommonName, "Test C2PA CA");
        ca_params.distinguished_name.push(DnType::OrganizationName, "Test");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let leaf_key = KeyPair::generate().unwrap();
        let mut leaf_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        leaf_params.distinguished_name.push(DnType::CommonName, "Test C2PA Signer");
        leaf_params.distinguished_name.push(DnType::OrganizationName, "Test");
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::EmailProtection];
        leaf_params.use_authority_key_identifier_extension = true;
        let leaf = leaf_params.signed_by(&leaf_key, &ca, &ca_key).unwrap();

        let chain = format!("{}{}", leaf.pem(), ca.pem());
        c2pa::create_signer::from_keys(
            chain.as_bytes(),
            leaf_key.serialize_pem().as_bytes(),
            c2pa::SigningAlg::Es256,
            None,
        )
        .unwrap()
    }

    fn capture_jpeg() -> Vec<u8> {
        let img = RgbImage::from_fn(640, 480, |x, y| Rgb([(x % 256) as u8, (y % 256) as u8, 90]));
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, 90)
            .write_image(img.as_raw(), 640, 480, ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    fn read(jpeg: &[u8]) -> Value {
        let reader = Reader::default()
            .with_stream("image/jpeg", Cursor::new(jpeg))
            .unwrap();
        serde_json::from_str(&reader.json()).unwrap()
    }

    /// Everything a reader reports as a failure, bar the one expected with a
    /// self-issued chain: not being on the C2PA trust list.
    fn unexpected_failures(report: &Value) -> Vec<String> {
        let mut codes = Vec::new();
        collect_failure_codes(report, &mut codes);
        codes.retain(|c| c != "signingCredential.untrusted");
        codes
    }

    fn collect_failure_codes(value: &Value, out: &mut Vec<String>) {
        match value {
            Value::Object(map) => {
                for (key, v) in map {
                    if key == "failure" {
                        if let Value::Array(items) = v {
                            for item in items {
                                if let Some(code) = item.get("code").and_then(Value::as_str) {
                                    out.push(code.to_string());
                                }
                            }
                        }
                    }
                    collect_failure_codes(v, out);
                }
            }
            Value::Array(items) => items.iter().for_each(|v| collect_failure_codes(v, out)),
            _ => {}
        }
    }

    fn active_manifest(report: &Value) -> &Value {
        let label = report["active_manifest"].as_str().unwrap();
        &report["manifests"][label]
    }

    fn actions(manifest: &Value) -> Vec<Value> {
        manifest["assertions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["label"].as_str().is_some_and(|l| l.starts_with("c2pa.actions")))
            .flat_map(|a| a["data"]["actions"].as_array().unwrap().clone())
            .collect()
    }

    #[test]
    fn capture_is_signed_as_a_digital_capture() {
        let signer = test_signer();
        let signed = sign_capture(&capture_jpeg(), signer.as_ref()).unwrap();
        let report = read(&signed);
        assert_eq!(unexpected_failures(&report), Vec::<String>::new(), "{report:#}");

        let actions = actions(active_manifest(&report));
        assert_eq!(actions[0]["action"], "c2pa.created");
        assert_eq!(actions[0]["digitalSourceType"], DIGITAL_CAPTURE_URI);
    }

    #[test]
    fn watermarked_photo_carries_the_signed_capture_as_its_parent() {
        let signer = test_signer();
        let signed_capture = sign_capture(&capture_jpeg(), signer.as_ref()).unwrap();
        let watermarked = sign_watermarked(&signed_capture, signer.as_ref()).unwrap();

        let report = read(&watermarked);
        assert_eq!(unexpected_failures(&report), Vec::<String>::new(), "{report:#}");

        let manifest = active_manifest(&report);
        let photo_actions = actions(manifest);
        let names: Vec<&str> = photo_actions.iter().map(|a| a["action"].as_str().unwrap()).collect();
        assert_eq!(names, ["c2pa.opened", "c2pa.placed"]);

        let ingredients = manifest["ingredients"].as_array().unwrap();
        assert_eq!(ingredients.len(), 2);
        assert_eq!(ingredients[0]["relationship"], "parentOf");
        assert_eq!(ingredients[1]["relationship"], "componentOf");
        assert_eq!(ingredients[1]["title"], "the-human-internet-brand-mark.png");

        // The mark carries its own credentials, with a JPEG claim thumbnail
        // — what the viewer pictures the ingredient from.
        let mark_label = ingredients[1]["active_manifest"].as_str().unwrap();
        let mark_manifest = &report["manifests"][mark_label];
        assert_eq!(mark_manifest["thumbnail"]["format"], "image/jpeg");
        let mark_actions = actions(mark_manifest);
        assert_eq!(mark_actions[0]["action"], "c2pa.created");
        assert_eq!(mark_actions[0]["digitalSourceType"], DIGITAL_CREATION_URI);
        // Without an embedded thumbnail a C2PA viewer shows the ingredient
        // as a blank card — it has no other way to get at the capture's
        // pixels. Needs c2pa's `add_thumbnails` feature.
        assert!(ingredients[0]["thumbnail"].is_object(), "{:#}", ingredients[0]);
        assert!(manifest["thumbnail"].is_object(), "{manifest:#}");

        // The ingredient is the signed capture: its own manifest, carried
        // along, still says created + digitalCapture.
        let capture_label = ingredients[0]["active_manifest"].as_str().unwrap();
        let capture_actions = actions(&report["manifests"][capture_label]);
        assert_eq!(capture_actions[0]["action"], "c2pa.created");
        assert_eq!(capture_actions[0]["digitalSourceType"], DIGITAL_CAPTURE_URI);

        // And the pixels really did change: this is a new asset, not a copy.
        assert_ne!(
            image::load_from_memory(&watermarked).unwrap().into_rgb8().get_pixel(600, 40),
            image::load_from_memory(&signed_capture).unwrap().into_rgb8().get_pixel(600, 40),
        );
    }

    /// `/pipeline`: the capture signed, then watermarked straight from memory
    /// with no re-read in between. Both outputs must be exactly what
    /// `/capture` and `/watermark` would have made.
    #[test]
    fn pipeline_signs_the_original_and_a_photo_descended_from_it() {
        let signer = test_signer();
        let original = sign_capture(&capture_jpeg(), signer.as_ref()).unwrap();
        let photo = watermark_signed_capture(&original, signer.as_ref()).unwrap();

        // The original: a capture, and nothing else.
        let original_report = read(&original);
        assert_eq!(unexpected_failures(&original_report), Vec::<String>::new(), "{original_report:#}");
        let original_actions = actions(active_manifest(&original_report));
        assert_eq!(original_actions.len(), 1);
        assert_eq!(original_actions[0]["action"], "c2pa.created");
        assert_eq!(original_actions[0]["digitalSourceType"], DIGITAL_CAPTURE_URI);

        // The photo: opened from the original, mark placed.
        let photo_report = read(&photo);
        assert_eq!(unexpected_failures(&photo_report), Vec::<String>::new(), "{photo_report:#}");
        let manifest = active_manifest(&photo_report);
        let names: Vec<String> = actions(manifest)
            .iter()
            .map(|a| a["action"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(names, ["c2pa.opened", "c2pa.placed"]);
        let ingredients = manifest["ingredients"].as_array().unwrap();
        assert_eq!(ingredients.len(), 2);
        assert_eq!(ingredients[1]["relationship"], "componentOf");

        // Its parent is this very original: the manifest the ingredient
        // carries is the one the original was signed with (manifest labels
        // are unique per signing), and it still says created + digitalCapture.
        assert_eq!(ingredients[0]["relationship"], "parentOf");
        let original_label = original_report["active_manifest"].as_str().unwrap();
        assert_eq!(ingredients[0]["active_manifest"], original_label);
        let carried_actions = actions(&photo_report["manifests"][original_label]);
        assert_eq!(carried_actions[0]["action"], "c2pa.created");
        assert_eq!(carried_actions[0]["digitalSourceType"], DIGITAL_CAPTURE_URI);
    }

    #[test]
    fn watermarking_refuses_an_unsigned_capture() {
        let signer = test_signer();
        let err = sign_watermarked(&capture_jpeg(), signer.as_ref()).unwrap_err();
        assert!(err.to_string().contains("not a signed capture"), "{err}");
    }
}

