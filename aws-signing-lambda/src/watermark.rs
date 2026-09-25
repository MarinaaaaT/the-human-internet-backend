//! Burns the brand mark into a capture's pixels, server-side.
//!
//! Moved here from the app (`DesignSystem/PhotoWatermarker.swift`) so the
//! watermarked photo is something this Lambda *produced* from a capture it
//! had already signed, rather than bytes a client says it watermarked — the
//! second manifest then records an edit the signer actually performed.
//!
//! **The mark is an image: `assets/brand-mark.png`.** The same file ships in
//! the app's asset catalog as `BrandMarkWatermark`, where `PhotoWatermarker`
//! (legacy/Skip-C2PA paths) and `ProvisionalWatermark` (the overlay drawn
//! over a capture still processing) draw it. To change the artwork, replace
//! the PNG in both places — nothing else. Placement is the other half of the
//! contract, and is stated relative to the image so any artwork fits: width
//! 9% of the photo's shorter side, height from the PNG's own aspect ratio,
//! inset 3.5% of the shorter side from the top-trailing corner. Artwork
//! should be sRGB, transparent where it isn't mark, and at least ~600px wide
//! (9% of a 48MP capture's shorter side is 544px).

use anyhow::{Context, Result};
use image::{
    codecs::jpeg::JpegEncoder, imageops, DynamicImage, ExtendedColorType, ImageDecoder,
    ImageEncoder, ImageReader, Rgba32FImage, RgbImage,
};
use std::io::Cursor;
use std::sync::OnceLock;

/// Mark width as a fraction of the image's shorter side.
pub const MARK_SIZE_FRACTION: f32 = 0.09;
/// Inset from the top and trailing edges, same basis.
pub const MARK_PADDING_FRACTION: f32 = 0.035;
/// Matches `UIImage.jpegData(compressionQuality: 0.95)` in `PhotoWatermarker`.
const JPEG_QUALITY: u8 = 95;

/// The artwork. Identical to the app's `BrandMarkWatermark` image set.
const BRAND_MARK_PNG: &[u8] = include_bytes!("../assets/brand-mark.png");

/// Returns `jpeg` with the brand mark burned in, re-encoded as a JPEG.
///
/// EXIF orientation is applied to the pixels (a raw iPhone capture is almost
/// always stored sideways and tagged), so the mark lands in the corner a
/// viewer sees and the output needs no orientation tag — the same thing
/// UIKit's redraw did on device. The ICC profile is carried over; other
/// metadata (EXIF, GPS) is dropped, as it was on device.
pub fn watermark_jpeg(jpeg: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ImageReader::new(Cursor::new(jpeg))
        .with_guessed_format()?
        .into_decoder()
        .context("capture is not a decodable image")?;
    let orientation = decoder.orientation()?;
    let icc_profile = decoder.icc_profile()?;
    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);
    let mut rgb = image.into_rgb8();

    // An iPhone capture is tagged Display P3; the artwork is sRGB. Pasting
    // sRGB values straight into P3 pixels would come out visibly more
    // saturated than the app's own (colour-managed) rendering of the mark.
    let is_display_p3 = icc_profile
        .as_deref()
        .is_some_and(|icc| contains(icc, b"Display P3") || contains(icc, &utf16be("Display P3")));
    draw_mark(&mut rgb, is_display_p3)?;

    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY);
    if let Some(icc) = icc_profile {
        // Unsupported only for formats without ICC support; JPEG has it.
        let _ = encoder.set_icc_profile(icc);
    }
    encoder.write_image(rgb.as_raw(), rgb.width(), rgb.height(), ExtendedColorType::Rgb8)?;
    Ok(out)
}

/// Where the mark goes on a `width`×`height` photo: its top-left corner
/// and its width, in pixels. Its height is the width times the artwork's
/// aspect ratio.
pub fn mark_placement(width: u32, height: u32) -> (f32, f32, f32) {
    let shorter = width.min(height) as f32;
    let size = shorter * MARK_SIZE_FRACTION;
    let padding = shorter * MARK_PADDING_FRACTION;
    (width as f32 - size - padding, padding, size)
}

/// The artwork, decoded once per Lambda instance, with its alpha
/// premultiplied so resampling doesn't drag the (meaningless) colour of
/// transparent pixels into the mark's edges as a dark fringe.
fn brand_mark() -> Result<&'static Rgba32FImage> {
    static MARK: OnceLock<Rgba32FImage> = OnceLock::new();
    if let Some(mark) = MARK.get() {
        return Ok(mark);
    }
    let mut mark = image::load_from_memory(BRAND_MARK_PNG)
        .context("brand-mark.png is not a decodable image")?
        .into_rgba32f();
    for px in mark.pixels_mut() {
        let a = px.0[3];
        for c in &mut px.0[..3] {
            *c *= a;
        }
    }
    Ok(MARK.get_or_init(|| mark))
}

/// The artwork's height / width.
pub fn mark_aspect_ratio() -> Result<f32> {
    let mark = brand_mark()?;
    Ok(mark.height() as f32 / mark.width() as f32)
}

fn draw_mark(image: &mut RgbImage, to_display_p3: bool) -> Result<()> {
    let (x, y, width) = mark_placement(image.width(), image.height());
    let height = width * mark_aspect_ratio()?;
    let scaled = imageops::resize(
        brand_mark()?,
        width.round().max(1.0) as u32,
        height.round().max(1.0) as u32,
        imageops::FilterType::Lanczos3,
    );

    let (left, top) = (x.round() as i64, y.round() as i64);
    for (mx, my, px) in scaled.enumerate_pixels() {
        let (dx, dy) = (left + mx as i64, top + my as i64);
        if dx < 0 || dy < 0 || dx >= image.width() as i64 || dy >= image.height() as i64 {
            continue;
        }
        // Lanczos rings slightly past [0, 1]; clamp before un-premultiplying.
        let alpha = px.0[3].clamp(0.0, 1.0);
        if alpha <= 0.0 {
            continue;
        }
        let mut color = [px.0[0], px.0[1], px.0[2]].map(|c| (c / alpha).clamp(0.0, 1.0));
        if to_display_p3 {
            color = srgb_to_display_p3(color);
        }
        let dst = image.get_pixel_mut(dx as u32, dy as u32);
        for (d, s) in dst.0.iter_mut().zip(color) {
            let blended = s * alpha + (*d as f32 / 255.0) * (1.0 - alpha);
            *d = (blended * 255.0).round().clamp(0.0, 255.0) as u8;
        }
    }
    Ok(())
}

/// Re-expresses a gamma-encoded sRGB colour in Display P3 (same primaries'
/// white point and transfer curve, wider gamut), so it looks the same once
/// the photo is shown through its P3 profile.
pub fn srgb_to_display_p3(rgb: [f32; 3]) -> [f32; 3] {
    fn decode(v: f32) -> f32 {
        if v <= 0.04045 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) }
    }
    fn encode(v: f32) -> f32 {
        let v = v.clamp(0.0, 1.0);
        if v <= 0.003_130_8 { v * 12.92 } else { 1.055 * v.powf(1.0 / 2.4) - 0.055 }
    }
    let [r, g, b] = rgb.map(decode);
    [
        encode(0.822_462 * r + 0.177_538 * g),
        encode(0.033_194 * r + 0.966_806 * g),
        encode(0.017_083 * r + 0.072_397 * g + 0.910_520 * b),
    ]
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// ICC v4 descriptions (Apple's Display P3 profile) are UTF-16BE.
fn utf16be(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_be_bytes()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GenericImageView, Rgb};

    fn gray_jpeg(width: u32, height: u32) -> Vec<u8> {
        let img = RgbImage::from_pixel(width, height, Rgb([40, 40, 40]));
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, 95)
            .write_image(img.as_raw(), width, height, ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    fn decode(jpeg: &[u8]) -> RgbImage {
        image::load_from_memory(jpeg).unwrap().into_rgb8()
    }

    /// The stand-in artwork's colour — `Theme.accentPink`.
    const PINK_SRGB: [u8; 3] = [227, 168, 222];

    fn is_pink(p: &Rgb<u8>) -> bool {
        p.0[0].abs_diff(PINK_SRGB[0]) < 12
            && p.0[1].abs_diff(PINK_SRGB[1]) < 12
            && p.0[2].abs_diff(PINK_SRGB[2]) < 12
    }

    #[test]
    fn mark_lands_top_trailing_and_nowhere_else() {
        let out = decode(&watermark_jpeg(&gray_jpeg(1000, 800)).unwrap());
        assert_eq!(out.dimensions(), (1000, 800));

        let (x, y, size) = mark_placement(1000, 800);
        assert_eq!((x, y, size), (1000.0 - 72.0 - 28.0, 28.0, 72.0));
        // Middle of the top capsule, and middle of the body below it.
        assert!(is_pink(out.get_pixel((x + size / 2.0) as u32, (y + size * 0.11) as u32)));
        assert!(is_pink(out.get_pixel((x + size / 2.0) as u32, (y + size * 0.5) as u32)));
        // Beside the body, under the capsule's overhang: background.
        assert!(!is_pink(out.get_pixel((x + size * 0.1) as u32, (y + size * 0.6) as u32)));
        // Other corners untouched.
        for (px, py) in [(10, 10), (10, 790), (990, 790)] {
            assert!(!is_pink(out.get_pixel(px, py)));
        }
    }

    #[test]
    fn portrait_uses_the_shorter_side() {
        let (_, _, size) = mark_placement(3024, 4032);
        assert!((size - 3024.0 * 0.09).abs() < 0.01);
    }

    /// An iPhone stores a portrait capture as a landscape bitmap tagged
    /// orientation 6 (rotate 90° clockwise to view). The mark must be placed
    /// on the upright image, and the output must be upright.
    #[test]
    fn exif_orientation_is_applied_before_placing_the_mark() {
        let landscape = gray_jpeg(400, 300);
        let tagged = with_exif_orientation(&landscape, 6);
        let out = decode(&watermark_jpeg(&tagged).unwrap());
        assert_eq!(out.dimensions(), (300, 400), "output should be the upright portrait");

        let (x, y, size) = mark_placement(300, 400);
        assert!(is_pink(out.get_pixel((x + size / 2.0) as u32, (y + size * 0.5) as u32)));
    }

    /// `Theme.accentPink` in P3, as UIKit would convert it: (218, 171, 219).
    #[test]
    fn srgb_pink_converts_to_the_expected_display_p3_values() {
        let p3 = srgb_to_display_p3(PINK_SRGB.map(|c| c as f32 / 255.0)).map(|c| (c * 255.0).round() as u8);
        for (got, want) in p3.iter().zip([218u8, 171, 219]) {
            assert!(got.abs_diff(want) <= 1, "{p3:?}");
        }
        // Greys are the same in both spaces.
        let grey = srgb_to_display_p3([0.5, 0.5, 0.5]);
        assert!(grey.iter().all(|c| (c - 0.5).abs() < 0.002), "{grey:?}");
    }

    /// Must be the same PNG as the app's `BrandMarkWatermark` image set —
    /// the app's `CapturePipelineTests` pins the same dimensions. When the
    /// artwork changes, replace it in both repos and update both tests.
    #[test]
    fn artwork_is_the_shared_png_and_large_enough_for_a_48mp_capture() {
        let mark = brand_mark().unwrap();
        assert_eq!(mark.dimensions(), (1024, 860));
        assert!(mark.width() >= 544, "a 48MP capture's mark is 544px wide");
    }

    #[test]
    fn non_images_are_rejected() {
        assert!(watermark_jpeg(b"definitely not a jpeg").is_err());
    }

    /// Inserts a minimal APP1/EXIF segment carrying just an Orientation tag
    /// straight after SOI.
    fn with_exif_orientation(jpeg: &[u8], orientation: u16) -> Vec<u8> {
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
        let decoded = image::load_from_memory(&out).unwrap();
        assert_eq!(decoded.dimensions(), (400, 300), "fixture should decode un-rotated");
        out
    }
}

