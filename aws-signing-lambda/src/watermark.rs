//! Burns the brand mark into a capture's pixels, server-side.
//!
//! Moved here from the app (`DesignSystem/PhotoWatermarker.swift`) so the
//! watermarked photo is something this Lambda *produced* from a capture it
//! had already signed, rather than bytes a client says it watermarked — the
//! second manifest then records an edit the signer actually performed.
//!
//! The geometry is a contract with two Swift copies that must look the same:
//! `PhotoWatermarker` (still used on the legacy/Skip-C2PA paths) and
//! `ProvisionalWatermark` (the overlay the app draws over a capture while it's
//! still processing, so the swap to the real watermarked photo is invisible).
//! Both lay out SwiftUI's `BrandMark`: a horizontal capsule over a narrower
//! vertical one, `size` = 9% of the image's shorter side, inset 3.5% of it
//! from the top-trailing corner.

use anyhow::{Context, Result};
use image::{
    codecs::jpeg::JpegEncoder, DynamicImage, ExtendedColorType, ImageDecoder, ImageEncoder,
    ImageReader, RgbImage,
};
use std::io::Cursor;
use tiny_skia::{FillRule, Paint, PathBuilder, Pixmap, Transform};

/// Mark width as a fraction of the image's shorter side.
pub const MARK_SIZE_FRACTION: f32 = 0.09;
/// Inset from the top and trailing edges, same basis.
pub const MARK_PADDING_FRACTION: f32 = 0.035;
/// Matches `UIImage.jpegData(compressionQuality: 0.95)` in `PhotoWatermarker`.
const JPEG_QUALITY: u8 = 95;

/// `Theme.accentPink` — SwiftUI `Color(red: 0.89, green: 0.66, blue: 0.87)`,
/// which is sRGB.
const PINK_SRGB: [u8; 3] = [227, 168, 222];
/// The same colour expressed in Display P3, which is what an iPhone capture
/// is tagged with. Painting the sRGB triple straight into P3 pixels would
/// come out visibly more saturated than the app's own rendering of the mark.
const PINK_DISPLAY_P3: [u8; 3] = [218, 171, 219];

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

    let is_display_p3 = icc_profile
        .as_deref()
        .is_some_and(|icc| contains(icc, b"Display P3") || contains(icc, &utf16be("Display P3")));
    let pink = if is_display_p3 { PINK_DISPLAY_P3 } else { PINK_SRGB };
    draw_mark(&mut rgb, pink)?;

    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, JPEG_QUALITY);
    if let Some(icc) = icc_profile {
        // Unsupported only for formats without ICC support; JPEG has it.
        let _ = encoder.set_icc_profile(icc);
    }
    encoder.write_image(rgb.as_raw(), rgb.width(), rgb.height(), ExtendedColorType::Rgb8)?;
    Ok(out)
}

/// Where the mark goes on a `width`×`height` image: its top-left corner and
/// its `size` (width; it's 0.84×size tall), in pixels.
pub fn mark_placement(width: u32, height: u32) -> (f32, f32, f32) {
    let shorter = width.min(height) as f32;
    let size = shorter * MARK_SIZE_FRACTION;
    let padding = shorter * MARK_PADDING_FRACTION;
    (width as f32 - size - padding, padding, size)
}

fn draw_mark(image: &mut RgbImage, pink: [u8; 3]) -> Result<()> {
    let (x, y, size) = mark_placement(image.width(), image.height());

    // Rasterise just the mark's bounding box, keeping the sub-pixel offset
    // so anti-aliased edges fall where UIKit's would.
    let left = x.floor();
    let top = y.floor();
    let right = (x + size).ceil().min(image.width() as f32);
    let bottom = (y + size * 0.84).ceil().min(image.height() as f32);
    let mut pixmap = Pixmap::new((right - left) as u32, (bottom - top) as u32)
        .context("mark region is empty")?;

    let mut paint = Paint::default();
    paint.set_color_rgba8(pink[0], pink[1], pink[2], 255);
    paint.anti_alias = true;
    let transform = Transform::from_translate(x - left, y - top);

    // SwiftUI `BrandMark`: VStack(spacing: 0) {
    //   Capsule().frame(width: size, height: size * 0.22)
    //   RoundedRectangle(cornerRadius: size * 0.3)
    //     .frame(width: size * 0.5, height: size * 0.62).offset(y: -size * 0.04)
    // }
    // The rectangle's 0.3 radius is clamped to half its 0.5 width, so it is
    // a vertical capsule too.
    for (rx, ry, rw, rh) in [
        (0.0, 0.0, size, size * 0.22),
        (size * 0.25, size * 0.22 - size * 0.04, size * 0.5, size * 0.62),
    ] {
        let path = capsule(rx, ry, rw, rh).context("degenerate mark shape")?;
        pixmap.fill_path(&path, &paint, FillRule::Winding, transform, None);
    }

    // Source-over, from tiny-skia's premultiplied RGBA onto opaque RGB.
    let width = pixmap.width();
    for (i, px) in pixmap.pixels().iter().enumerate() {
        let alpha = px.alpha() as u32;
        if alpha == 0 {
            continue;
        }
        let dx = left as u32 + i as u32 % width;
        let dy = top as u32 + i as u32 / width;
        let dst = image.get_pixel_mut(dx, dy);
        let src = [px.red(), px.green(), px.blue()];
        for (d, s) in dst.0.iter_mut().zip(src) {
            *d = (s as u32 + (*d as u32 * (255 - alpha) + 127) / 255) as u8;
        }
    }
    Ok(())
}

/// A rounded rectangle whose corner radius is half its shorter side.
fn capsule(x: f32, y: f32, w: f32, h: f32) -> Option<tiny_skia::Path> {
    let r = w.min(h) / 2.0;
    // Cubic Bézier quarter-circle constant.
    let k = r * 0.552_284_8;
    let mut pb = PathBuilder::new();
    pb.move_to(x + r, y);
    pb.line_to(x + w - r, y);
    pb.cubic_to(x + w - r + k, y, x + w, y + r - k, x + w, y + r);
    pb.line_to(x + w, y + h - r);
    pb.cubic_to(x + w, y + h - r + k, x + w - r + k, y + h, x + w - r, y + h);
    pb.line_to(x + r, y + h);
    pb.cubic_to(x + r - k, y + h, x, y + h - r + k, x, y + h - r);
    pb.line_to(x, y + r);
    pb.cubic_to(x, y + r - k, x + r - k, y, x + r, y);
    pb.close();
    pb.finish()
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
