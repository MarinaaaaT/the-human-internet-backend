//! Fixtures shared by the tests.

use image::{codecs::jpeg::JpegEncoder, ExtendedColorType, ImageEncoder, Rgb, RgbImage};

/// Stands in for an ICC profile: decoders and encoders carry the bytes
/// through without parsing them. Names Display P3, as an iPhone's does.
pub const TEST_ICC: &[u8] = b"stand-in ICC profile: Display P3";

/// A point on the brand mark's solid stroke, in fractions of the mark's box:
/// the spiral's outer ring (1–12% across, halfway down the artwork).
pub const ON_STROKE: (f32, f32) = (0.065, 0.5);
/// The gap between the outer ring and the next (13–20%), same row.
pub const OFF_STROKE: (f32, f32) = (0.165, 0.5);

/// Left half red, right half blue: which way up it is shows at a glance.
pub fn two_tone(width: u32, height: u32) -> RgbImage {
    RgbImage::from_fn(width, height, |x, _| if x < width / 2 { Rgb([230, 20, 20]) } else { Rgb([20, 20, 230]) })
}

pub fn jpeg(rgb: &RgbImage, icc_profile: Option<&[u8]>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, 90);
    if let Some(icc) = icc_profile {
        encoder.set_icc_profile(icc.to_vec()).unwrap();
    }
    encoder.write_image(rgb.as_raw(), rgb.width(), rgb.height(), ExtendedColorType::Rgb8).unwrap();
    out
}

/// Inserts a minimal APP1/EXIF segment carrying just an Orientation tag
/// straight after SOI.
pub fn with_exif_orientation(jpeg: &[u8], orientation: u16) -> Vec<u8> {
    let mut tiff = vec![b'M', b'M', 0, 42, 0, 0, 0, 8]; // big-endian, IFD0 at 8
    tiff.extend_from_slice(&1u16.to_be_bytes()); // one entry
    tiff.extend_from_slice(&0x0112u16.to_be_bytes()); // Orientation
    tiff.extend_from_slice(&3u16.to_be_bytes()); // SHORT
    tiff.extend_from_slice(&1u32.to_be_bytes()); // count
    tiff.extend_from_slice(&orientation.to_be_bytes());
    tiff.extend_from_slice(&[0, 0]);
    tiff.extend_from_slice(&0u32.to_be_bytes()); // no next IFD
    let mut payload = b"Exif\0\0".to_vec();
    payload.extend_from_slice(&tiff);
    let mut out = jpeg[..2].to_vec();
    out.extend_from_slice(&[0xFF, 0xE1]);
    out.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
    out.extend_from_slice(&payload);
    out.extend_from_slice(&jpeg[2..]);
    assert_eq!(
        image::load_from_memory(&out).unwrap().into_rgb8().dimensions(),
        image::load_from_memory(jpeg).unwrap().into_rgb8().dimensions(),
        "the fixture should decode un-rotated: only orientation-aware decoding turns it"
    );
    out
}

/// For a [`two_tone`] stored sideways with orientation 6 (rotate 90°
/// clockwise to view), as an iPhone stores a portrait: upright, its stored
/// left half is on top.
pub fn assert_red_on_top_blue_below(upright: &RgbImage) {
    let (w, h) = upright.dimensions();
    assert!(h > w, "upright should be portrait: {w}x{h}");
    let top = upright.get_pixel(w / 2, h / 8).0;
    let bottom = upright.get_pixel(w / 2, h * 7 / 8).0;
    assert!(top[0] > 180 && top[2] < 80, "top {top:?}");
    assert!(bottom[2] > 180 && bottom[0] < 80, "bottom {bottom:?}");
}
