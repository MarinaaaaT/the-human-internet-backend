use anyhow::anyhow;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use c2pa::{Builder, Context, Reader, ResourceRef, Result as C2paResult, Signer};
use std::io::Cursor;
use std::time::Instant;

use crate::watermark::{self, DecodedCapture};
use crate::{thumbnail, timing};

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

/// Resource ids of the claim thumbnails supplied in each manifest — see
/// `thumbnail.rs`.
const CAPTURE_THUMBNAIL_ID: &str = "capture-thumbnail.jpg";
const PHOTO_THUMBNAIL_ID: &str = "photo-thumbnail.jpg";
const MARK_THUMBNAIL_ID: &str = "brand-mark-thumbnail.jpg";

/// What a claim thumbnail's assertion is called (`c2pa.thumbnail.claim`, with
/// a format suffix in v1 claims).
const CLAIM_THUMBNAIL_ASSERTION: &str = "c2pa.thumbnail.claim";

/// The capture's manifest: `c2pa.created` + `digitalCapture` — "a real
/// camera took this", the claim the whole product rests on. With a supplied
/// thumbnail unless `/capture` couldn't make one, when c2pa makes it.
///
/// Hand-written JSON rather than typed assertion builders: c2pa-rs's v2
/// actions assertion wants camelCase `digitalSourceType`, and the typed
/// builders don't reliably produce that (the old on-device signer in the
/// app hit the same thing).
fn capture_manifest_json(with_thumbnail: bool) -> String {
    let thumbnail = if with_thumbnail {
        format!(r#""thumbnail": {{ "format": "{}", "identifier": "{CAPTURE_THUMBNAIL_ID}" }},"#, thumbnail::FORMAT)
    } else {
        String::new()
    };
    format!(
        r#"{{
  "claim_version": 2,
  "format": "image/jpeg",
  "title": "the-human-internet-capture.jpg",
  "claim_generator_info": [
    {{ "name": "the-human-internet" }}
  ],
  {thumbnail}
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
  "thumbnail": {{ "format": "{}", "identifier": "{PHOTO_THUMBNAIL_ID}" }},
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
}}"#,
        thumbnail::FORMAT
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
/// signed JPEG bytes: the `/capture` route — step one of the two-call capture
/// pipeline, and all a build predating server-side watermarking needs.
///
/// Its thumbnail comes from a reduced-scale decode
/// ([`thumbnail::from_jpeg_scaled`]), since nothing else here needs the
/// pixels. A JPEG that decoder can't read is left to c2pa's own thumbnail
/// (`add_thumbnails`), as every capture was before.
///
/// Blocking — callers on an async runtime should run this via
/// `spawn_blocking` (see main.rs), both because c2pa-rs's Builder is
/// synchronous and because `KmsSigner::sign` itself blocks on a KMS call.
pub fn sign_capture(image_data: &[u8], signer: &dyn Signer) -> C2paResult<Vec<u8>> {
    let thumbnail = thumbnail::from_jpeg_scaled(image_data)
        .inspect_err(|error| {
            tracing::warn!(error = %format!("{error:#}"), "no scaled thumbnail; c2pa will make one")
        })
        .ok();
    sign_capture_with(image_data, thumbnail.as_deref(), signer)
}

/// The first half of `/pipeline`: decodes the raw capture — the only decode
/// the whole pipeline does — signs it as the original, with a thumbnail from
/// those pixels, and hands the pixels back for [`watermark_signed_capture`].
///
/// They are the original's pixels as well as the raw capture's: signing only
/// inserts the manifest's APP11 segments, so both decode identically (pinned
/// by `the_signed_capture_decodes_to_the_raw_captures_pixels`). Blocking,
/// like [`sign_capture`].
pub fn sign_original(raw_capture: &[u8], signer: &dyn Signer) -> anyhow::Result<(Vec<u8>, DecodedCapture)> {
    let capture = watermark::decode_capture(raw_capture)?;
    let thumbnail = thumbnail::from_pixels("capture", &capture.rgb, capture.icc_profile.as_deref())?;
    let original = sign_capture_with(raw_capture, Some(&thumbnail), signer)?;
    Ok((original, capture))
}

fn sign_capture_with(image_data: &[u8], thumbnail: Option<&[u8]>, signer: &dyn Signer) -> C2paResult<Vec<u8>> {
    let mut builder = Builder::default().with_definition(capture_manifest_json(thumbnail.is_some()))?;
    if let Some(thumbnail) = thumbnail {
        builder.add_resource(CAPTURE_THUMBNAIL_ID, Cursor::new(thumbnail))?;
    }
    sign("capture", &mut builder, "image/jpeg", image_data, signer)
}

/// Step two of the capture pipeline (`/watermark`): takes a capture
/// *already signed* by `sign_capture`, decodes it, and does
/// [`watermark_signed_capture`].
///
/// Refuses input with no C2PA manifest, so the ingredient is always a signed
/// capture rather than bare pixels — this route only ever sees what
/// `sign-photo` got back from step one, but the chain is only worth anything
/// if its first link is always there. Blocking, like `sign_capture`.
pub fn sign_watermarked(signed_capture: &[u8], signer: &dyn Signer) -> anyhow::Result<Vec<u8>> {
    timing::time("check_input", || {
        Reader::default().with_stream("image/jpeg", Cursor::new(signed_capture))
    })
    .map_err(|e| anyhow!("input is not a signed capture: {e}"))?;
    let capture = watermark::decode_capture(signed_capture)?;
    watermark_signed_capture(signed_capture, capture, signer)
}

/// The watermark step itself: burns the brand mark into `capture` — the
/// decoded pixels of `signed_capture` — and signs the result with the signed
/// capture as its parent ingredient and the mark as drawn (see
/// [`watermark::Watermarked::mark_png`]), itself signed, as a component
/// ingredient. Returns the watermarked JPEG, whose claim thumbnail is made
/// from its own pixels, mark included.
///
/// `/watermark` gets here through [`sign_watermarked`], which first checks
/// its input really is a signed capture. `/pipeline` calls this directly, on
/// what [`sign_original`] returned a moment earlier in the same invocation:
/// those bytes never left this Lambda, so reading them back would prove
/// nothing, and their pixels are the ones it already decoded. Blocking, like
/// `sign_capture`.
pub fn watermark_signed_capture(
    signed_capture: &[u8],
    capture: DecodedCapture,
    signer: &dyn Signer,
) -> anyhow::Result<Vec<u8>> {
    let watermark::Watermarked { jpeg: watermarked, thumbnail_jpeg, mark_png, mark_thumbnail_jpeg } =
        watermark::watermark(capture)?;

    let mut builder = Builder::default().with_definition(watermarked_manifest_json())?;
    builder.add_resource(PHOTO_THUMBNAIL_ID, Cursor::new(thumbnail_jpeg))?;
    add_signed_ingredient(
        &mut builder,
        "the-human-internet-capture.jpg",
        "parentOf",
        CAPTURE_INGREDIENT_LABEL,
        "image/jpeg",
        signed_capture,
    )?;
    let signed_mark = sign_mark(&mark_png, mark_thumbnail_jpeg, signer)?;
    add_signed_ingredient(
        &mut builder,
        "the-human-internet-brand-mark.png",
        "componentOf",
        BRAND_MARK_INGREDIENT_LABEL,
        "image/png",
        &signed_mark,
    )?;

    Ok(sign("photo", &mut builder, "image/jpeg", &watermarked, signer)?)
}

/// Adds an asset this Lambda signed as an ingredient whose thumbnail is a
/// reference to the asset's own claim thumbnail (C2PA 2.2 §18.13.1.2) —
/// what a viewer pictures the ingredient by — rather than a new one.
///
/// c2pa-rs only makes that reference itself for an ingredient that validates
/// with no failure at all, and with a certificate that isn't on the C2PA
/// trust list (ours, until the Conformance Program) there is always one:
/// `signingCredential.untrusted`. It then decodes the whole ingredient and
/// embeds a newly made `c2pa.thumbnail.ingredient` instead — for the capture,
/// a second full decode of the same pixels; for the mark, a transparent PNG
/// enlarged to 1024px. Naming the thumbnail in the ingredient's definition
/// skips both: c2pa makes nothing when one is given, and writes the given
/// hashed reference as it is.
///
/// Should the asset have no claim thumbnail, c2pa makes one as before.
fn add_signed_ingredient(
    builder: &mut Builder,
    title: &str,
    relationship: &str,
    label: &'static str,
    format: &str,
    signed: &[u8],
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut ingredient = serde_json::json!({ "title": title, "relationship": relationship, "label": label });
    match claim_thumbnail_ref(format, signed) {
        Ok(Some(thumbnail)) => ingredient["thumbnail"] = serde_json::to_value(thumbnail)?,
        Ok(None) => tracing::warn!(ingredient = label, "ingredient has no claim thumbnail; c2pa will make one"),
        Err(error) => tracing::warn!(
            ingredient = label,
            error = %format!("{error:#}"),
            "couldn't find the ingredient's claim thumbnail; c2pa will make one"
        ),
    }
    builder.add_ingredient_from_stream(ingredient.to_string(), format, &mut Cursor::new(signed))?;
    tracing::info!(step = "add_ingredient", ingredient = label, ms = timing::ms_since(start), "timing");
    Ok(())
}

/// A hashed reference to `signed`'s own claim thumbnail, in the form an
/// ingredient definition takes: the absolute JUMBF URI of the assertion in
/// its manifest, with the hash that manifest's claim already records for it.
///
/// Read without validating: this only looks up where the thumbnail is.
/// `add_ingredient_from_stream` validates the ingredient in full and records
/// the result, as it always has, and a reference with the wrong hash would
/// fail the photo's own validation.
fn claim_thumbnail_ref(format: &str, signed: &[u8]) -> anyhow::Result<Option<ResourceRef>> {
    let context = Context::new().with_settings(r#"{"verify": {"verify_after_reading": false}}"#)?;
    let reader = Reader::from_context(context).with_stream(format, Cursor::new(signed))?;
    let Some(manifest) = reader.active_manifest() else {
        return Ok(None);
    };
    let (Some(thumbnail), Some(hashed)) = (
        manifest.thumbnail_ref(),
        manifest.assertion_references().find(|uri| uri.url().contains(CLAIM_THUMBNAIL_ASSERTION)),
    ) else {
        return Ok(None);
    };
    // The URI must be absolute, naming the ingredient's own manifest, or c2pa
    // treats it as a stale reference and drops it; `thumbnail_ref`'s is.
    let mut reference = ResourceRef::new(thumbnail.format.clone(), thumbnail.identifier.clone());
    reference.alg = hashed.alg();
    reference.hash = Some(BASE64.encode(hashed.hash()));
    Ok(Some(reference))
}

/// `Builder::sign`, timed as `manifest`'s signing.
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
    use crate::test_support::{
        assert_red_on_top_blue_below, jpeg, two_tone, with_exif_orientation, ON_STROKE, TEST_ICC,
    };
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
        serde_json::from_str(&reader(jpeg).json()).unwrap()
    }

    fn reader(jpeg: &[u8]) -> Reader {
        Reader::default().with_stream("image/jpeg", Cursor::new(jpeg)).unwrap()
    }

    /// `/pipeline`, in memory: the original and the photo.
    fn pipeline(raw_capture: &[u8], signer: &dyn Signer) -> (Vec<u8>, Vec<u8>) {
        let (original, capture) = sign_original(raw_capture, signer).unwrap();
        let photo = watermark_signed_capture(&original, capture, signer).unwrap();
        (original, photo)
    }

    /// `/capture` then `/watermark`, in memory.
    fn two_calls(raw_capture: &[u8], signer: &dyn Signer) -> (Vec<u8>, Vec<u8>) {
        let original = sign_capture(raw_capture, signer).unwrap();
        let photo = sign_watermarked(&original, signer).unwrap();
        (original, photo)
    }

    /// The labels of a photo's manifest, its parent's (the original's) and
    /// its brand mark's.
    fn photo_labels(photo: &Reader) -> [String; 3] {
        let manifest = photo.active_manifest().unwrap();
        let ingredients = manifest.ingredients();
        [
            photo.active_label().unwrap().to_string(),
            ingredients[0].active_manifest().unwrap().to_string(),
            ingredients[1].active_manifest().unwrap().to_string(),
        ]
    }

    /// The labels of the hashed assertions in manifest `label` that are
    /// thumbnails of any kind.
    fn thumbnail_assertions(reader: &Reader, label: &str) -> Vec<String> {
        reader
            .get_manifest(label)
            .unwrap()
            .assertion_references()
            .map(|uri| uri.url())
            .filter(|url| url.contains("c2pa.thumbnail"))
            .collect()
    }

    /// Where manifest `label`'s claim thumbnail is, as a reader reports it.
    fn own_claim_thumbnail(label: &str) -> String {
        format!("self#jumbf=/c2pa/{label}/c2pa.assertions/c2pa.thumbnail.claim")
    }

    /// Manifest `label`'s claim thumbnail, decoded.
    fn claim_thumbnail(reader: &Reader, label: &str) -> RgbImage {
        let thumbnail = reader.get_manifest(label).unwrap().thumbnail_ref().unwrap();
        assert_eq!(thumbnail.format, "image/jpeg");
        let mut jpeg = Cursor::new(Vec::new());
        reader.resource_to_stream(&thumbnail.identifier, &mut jpeg).unwrap();
        image::load_from_memory(&jpeg.into_inner()).unwrap().into_rgb8()
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

        // With the thumbnail this Lambda made, not one from c2pa.
        let reader = reader(&signed);
        let label = reader.active_label().unwrap();
        assert_eq!(thumbnail_assertions(&reader, label), [own_claim_thumbnail(label)]);
        assert_eq!(claim_thumbnail(&reader, label).dimensions(), (640, 480));
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
        // Without a thumbnail a C2PA viewer shows the ingredient as a blank
        // card — it has no other way to get at the capture's pixels. It's a
        // reference to the capture's own claim thumbnail; see
        // `the_photos_ingredients_reference_their_own_claim_thumbnails`.
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
        let (original, photo) = pipeline(&capture_jpeg(), signer.as_ref());

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

    /// The photo, the original and the brand mark each carry one claim
    /// thumbnail, the one supplied here — and the photo embeds no other
    /// thumbnail: no `c2pa.thumbnail.ingredient` of either ingredient.
    #[test]
    fn every_manifest_has_exactly_one_claim_thumbnail() {
        let signer = test_signer();
        for (route, (_, photo)) in [
            ("pipeline", pipeline(&capture_jpeg(), signer.as_ref())),
            ("two calls", two_calls(&capture_jpeg(), signer.as_ref())),
        ] {
            let reader = reader(&photo);
            for label in photo_labels(&reader) {
                assert_eq!(thumbnail_assertions(&reader, &label), [own_claim_thumbnail(&label)], "{route}");
            }
        }
    }

    /// The photo's ingredients are pictured by the claim thumbnails their
    /// own manifests carry (C2PA 2.2 §18.13.1.2): the parent by the
    /// original's, the mark by the mark's. Not a newly generated thumbnail of
    /// either, which is what c2pa makes for an ingredient signed with a
    /// certificate off the trust list unless it's told otherwise.
    #[test]
    fn the_photos_ingredients_reference_their_own_claim_thumbnails() {
        let signer = test_signer();
        for (route, (original, photo)) in [
            ("pipeline", pipeline(&capture_jpeg(), signer.as_ref())),
            ("two calls", two_calls(&capture_jpeg(), signer.as_ref())),
        ] {
            let photo_report = read(&photo);
            assert_eq!(unexpected_failures(&photo_report), Vec::<String>::new(), "{route}: {photo_report:#}");
            assert_eq!(photo_report["validation_state"], "Valid", "{route}");
            let ingredients = active_manifest(&photo_report)["ingredients"].as_array().unwrap();

            let original_report = read(&original);
            let original_label = original_report["active_manifest"].as_str().unwrap();
            assert_eq!(ingredients[0]["active_manifest"], original_label);
            assert_eq!(active_manifest(&original_report)["thumbnail"]["identifier"], own_claim_thumbnail(original_label));
            assert_eq!(ingredients[0]["thumbnail"]["identifier"], own_claim_thumbnail(original_label), "{route}");

            let mark_label = ingredients[1]["active_manifest"].as_str().unwrap();
            assert_eq!(ingredients[1]["thumbnail"]["identifier"], own_claim_thumbnail(mark_label), "{route}");
        }
    }

    /// An iPhone portrait: stored sideways, tagged orientation 6. Every
    /// thumbnail is of the upright picture, whichever route made it.
    #[test]
    fn an_orientation_6_capture_gets_upright_thumbnails() {
        let signer = test_signer();
        let raw = with_exif_orientation(&jpeg(&two_tone(1200, 900), Some(TEST_ICC)), 6);

        let capture = reader(&sign_capture(&raw, signer.as_ref()).unwrap());
        let thumbnail = claim_thumbnail(&capture, capture.active_label().unwrap());
        assert_eq!(thumbnail.dimensions(), (768, 1024), "/capture");
        assert_red_on_top_blue_below(&thumbnail);

        for (route, (_, photo)) in [
            ("pipeline", pipeline(&raw, signer.as_ref())),
            ("two calls", two_calls(&raw, signer.as_ref())),
        ] {
            let reader = reader(&photo);
            let [photo_label, original_label, _] = photo_labels(&reader);
            for label in [photo_label, original_label] {
                let thumbnail = claim_thumbnail(&reader, &label);
                assert_eq!(thumbnail.dimensions(), (768, 1024), "{route}: {label}");
                assert_red_on_top_blue_below(&thumbnail);
            }
        }
    }

    /// Each thumbnail is of its own asset: the photo's shows the mark it was
    /// given, top-trailing; the original's, made before there was one,
    /// doesn't.
    #[test]
    fn the_photos_thumbnail_shows_the_mark_and_the_originals_doesnt() {
        let signer = test_signer();
        let dark = RgbImage::from_pixel(1200, 900, Rgb([30; 3])); // so the mark is white
        let (_, photo) = pipeline(&jpeg(&dark, None), signer.as_ref());
        let reader = reader(&photo);
        let [photo_label, original_label, _] = photo_labels(&reader);
        let photo_thumbnail = claim_thumbnail(&reader, &photo_label);
        let original_thumbnail = claim_thumbnail(&reader, &original_label);
        assert_eq!(photo_thumbnail.dimensions(), (1024, 768));

        let (x, y, size) = watermark::mark_placement(1024, 768);
        let height = size * watermark::mark_aspect_ratio().unwrap();
        let on_stroke = ((x + size * ON_STROKE.0) as u32, (y + height * ON_STROKE.1) as u32);
        let luma = |image: &RgbImage, (px, py): (u32, u32)| image.get_pixel(px, py).0[1];
        assert!(luma(&photo_thumbnail, on_stroke) > 180, "{:?}", photo_thumbnail.get_pixel(on_stroke.0, on_stroke.1));
        assert!(luma(&original_thumbnail, on_stroke) < 60, "{:?}", original_thumbnail.get_pixel(on_stroke.0, on_stroke.1));
        // Elsewhere the two are the same picture.
        for corner in [(20, 20), (20, 740), (1000, 740)] {
            assert!(luma(&photo_thumbnail, corner).abs_diff(luma(&original_thumbnail, corner)) < 4);
        }
    }

    /// What `/pipeline` relies on to decode once: signing a capture adds its
    /// manifest and leaves the pixels alone, so the signed original decodes
    /// to exactly the raw capture's pixels — orientation and ICC profile
    /// included — and the photo `/pipeline` makes from the raw capture's
    /// pixels is pixel for pixel the one `/watermark` makes by decoding the
    /// original.
    #[test]
    fn the_signed_capture_decodes_to_the_raw_captures_pixels() {
        let signer = test_signer();
        let detailed = RgbImage::from_fn(1200, 900, |x, y| {
            Rgb([(x * 7 % 256) as u8, (y * 5 % 256) as u8, ((x ^ y) % 256) as u8])
        });
        let raw = with_exif_orientation(&jpeg(&detailed, Some(TEST_ICC)), 6);
        let (original, photo) = pipeline(&raw, signer.as_ref());
        assert_ne!(original, raw, "signing should have added a manifest");

        let from_raw = watermark::decode_capture(&raw).unwrap();
        let from_original = watermark::decode_capture(&original).unwrap();
        assert_eq!(from_original.rgb.dimensions(), (900, 1200));
        assert!(from_original.rgb == from_raw.rgb, "the signed capture's pixels differ from the raw capture's");
        assert_eq!(from_original.icc_profile.as_deref(), Some(TEST_ICC));
        assert_eq!(from_original.icc_profile, from_raw.icc_profile);

        let via_watermark = sign_watermarked(&original, signer.as_ref()).unwrap();
        let pixels = |jpeg: &[u8]| image::load_from_memory(jpeg).unwrap().into_rgb8();
        assert!(pixels(&photo) == pixels(&via_watermark), "/pipeline's photo differs from /watermark's");
    }
}

