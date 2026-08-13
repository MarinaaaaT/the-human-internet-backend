use c2pa::{Builder, Result as C2paResult};
use std::io::Cursor;

use crate::kms_signer::KmsSigner;

/// IPTC term asserting the image came off a physical capture device.
const DIGITAL_CAPTURE_URI: &str = "http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture";

/// Deliberately identical to `PhotoSigner.manifestJSON` in the iOS app,
/// down to the hand-written JSON: c2pa-rs's v2 actions assertion wants
/// camelCase `digitalSourceType`, and (per the iOS side's own hard-won
/// notes) the typed assertion builders don't reliably produce that. Keep
/// the two definitions in sync if the manifest shape ever changes —
/// there's no shared source between the Swift and Rust signers.
fn manifest_json() -> String {
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

/// Signs `image_data` (a JPEG) and returns the signed JPEG bytes. Blocking —
/// callers on an async runtime should run this via `spawn_blocking` (see
/// main.rs), both because c2pa-rs's Builder is synchronous and because
/// `KmsSigner::sign` itself blocks on a KMS call.
pub fn sign_jpeg(image_data: &[u8], signer: &KmsSigner) -> C2paResult<Vec<u8>> {
    let mut builder = Builder::default().with_definition(manifest_json())?;

    let mut source = Cursor::new(image_data);
    let mut dest = Cursor::new(Vec::new());

    builder.sign(signer, "image/jpeg", &mut source, &mut dest)?;

    Ok(dest.into_inner())
}
