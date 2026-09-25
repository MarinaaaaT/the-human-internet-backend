use c2pa::{Builder, Reader, Result as C2paResult, Signer};
use std::io::Cursor;

use crate::watermark;

/// IPTC term asserting the image came off a physical capture device.
const DIGITAL_CAPTURE_URI: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";

/// Label tying the watermarked photo's `c2pa.opened` action to its parent
/// ingredient (the signed capture) inside the manifest definition.
const CAPTURE_INGREDIENT_LABEL: &str = "capture";

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
/// ingredient), then edited — the brand mark burned in, by this Lambda.
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
            "action": "c2pa.edited",
            "description": "The Human Internet brand mark burned into the top-trailing corner"
          }}
        ]
      }}
    }}
  ]
}}"#
    )
}

/// Signs a capture (a JPEG) as-is, as a `digitalCapture`, and returns the
/// signed JPEG bytes. The `/capture` route: step one of the capture
/// pipeline, and all a build predating server-side watermarking needs.
///
/// Blocking — callers on an async runtime should run this via
/// `spawn_blocking` (see main.rs), both because c2pa-rs's Builder is
/// synchronous and because `KmsSigner::sign` itself blocks on a KMS call.
pub fn sign_capture(image_data: &[u8], signer: &dyn Signer) -> C2paResult<Vec<u8>> {
    let mut builder = Builder::default().with_definition(capture_manifest_json())?;

    let mut source = Cursor::new(image_data);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(signer, "image/jpeg", &mut source, &mut dest)?;

    Ok(dest.into_inner())
}

/// Step two of the capture pipeline (`/watermark`): takes a capture
/// *already signed* by `sign_capture`, burns the brand mark in, and signs the result with the
/// signed capture as its parent ingredient. Returns the watermarked JPEG.
///
/// Refuses input with no C2PA manifest, so the ingredient is always a signed
/// capture rather than bare pixels — this route only ever sees what
/// `sign-photo` got back from step one, but the chain is only worth anything
/// if its first link is always there. Blocking, like `sign_capture`.
pub fn sign_watermarked(signed_capture: &[u8], signer: &dyn Signer) -> anyhow::Result<Vec<u8>> {
    Reader::default()
        .with_stream("image/jpeg", Cursor::new(signed_capture))
        .map_err(|e| anyhow::anyhow!("input is not a signed capture: {e}"))?;

    let watermarked = watermark::watermark_jpeg(signed_capture)?;

    let mut builder = Builder::default().with_definition(watermarked_manifest_json())?;
    builder.add_ingredient_from_stream(
        format!(
            r#"{{ "title": "the-human-internet-capture.jpg", "relationship": "parentOf", "label": "{CAPTURE_INGREDIENT_LABEL}" }}"#
        ),
        "image/jpeg",
        &mut Cursor::new(signed_capture),
    )?;

    let mut source = Cursor::new(watermarked);
    let mut dest = Cursor::new(Vec::new());
    builder.sign(signer, "image/jpeg", &mut source, &mut dest)?;

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
        assert_eq!(names, ["c2pa.opened", "c2pa.edited"]);

        let ingredients = manifest["ingredients"].as_array().unwrap();
        assert_eq!(ingredients.len(), 1);
        assert_eq!(ingredients[0]["relationship"], "parentOf");

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

    #[test]
    fn watermarking_refuses_an_unsigned_capture() {
        let signer = test_signer();
        let err = sign_watermarked(&capture_jpeg(), signer.as_ref()).unwrap_err();
        assert!(err.to_string().contains("not a signed capture"), "{err}");
    }
}

