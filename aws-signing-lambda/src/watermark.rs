//! Burns the brand mark into a capture's pixels, server-side.
//!
//! Moved here from the app (`DesignSystem/PhotoWatermarker.swift`) so the
//! watermarked photo is something this Lambda *produced* from a capture it
//! had already signed, rather than bytes a client says it watermarked — the
//! second manifest then records an edit the signer actually performed.
//!
//! **The mark is an image: `assets/brand-mark.png`** — the spiral
//! "fingerprint", rendered from the website's `public/brand/mark.svg`. The
//! same file ships in the iOS app (`BrandMarkWatermark`) and the Android app
//! (`brand_mark_watermark`), where the on-device watermarkers and the
//! provisional overlay (drawn over a capture still processing) draw it. To
//! change the artwork, replace the PNG in all three repos — nothing else.
//! Only its **alpha** is used: it is the mark's shape, not its colour.
//!
//! **Colour adapts to the photo.** The mark is filled solid black or solid
//! white, whichever reads against the part of the photo it sits on — like the
//! iOS tab bar's glyphs over the live camera. [`mark_color`] decides, and all
//! four renderers implement the same rule: sample a 32×32 grid of points
//! across the mark's box, average their Rec. 709 luma (on the encoded 0–1
//! values), and draw black above 0.5, white at or below. The provisional
//! overlay samples a downscaled preview of the same capture, so for a box that
//! averages right at the threshold the two can disagree — the overlay is a
//! placeholder, and this is the colour that ships.
//!
//! Placement is the other half of the contract, and is stated relative to the
//! image so any artwork fits: width 9% of the photo's shorter side, height
//! from the PNG's own aspect ratio, inset 3.5% of the shorter side from the
//! top-trailing corner. Artwork should be transparent where it isn't mark and
//! at least ~600px wide (9% of a 48MP capture's shorter side is 544px).

use anyhow::{Context, Result};
use image::{
    codecs::{jpeg::JpegEncoder, png::PngEncoder},
    imageops, DynamicImage, ExtendedColorType, ImageDecoder, ImageEncoder, ImageReader,
    Rgba32FImage, RgbImage, RgbaImage,
};
use std::io::Cursor;
use std::sync::OnceLock;
use std::time::Instant;

use crate::{thumbnail, timing};

/// Mark width as a fraction of the image's shorter side.
pub const MARK_SIZE_FRACTION: f32 = 0.09;
/// Inset from the top and trailing edges, same basis.
pub const MARK_PADDING_FRACTION: f32 = 0.035;
/// Sample points per side of the grid [`mark_color`] averages.
pub const COLOR_SAMPLE_GRID: u32 = 32;
/// Mean luma above which the background counts as light, and the mark is black.
pub const LIGHT_BACKGROUND_LUMA: f32 = 0.5;
/// Matches `UIImage.jpegData(compressionQuality: 0.95)` in `PhotoWatermarker`.
const JPEG_QUALITY: u8 = 95;
/// Lower qualities tried, in order, when a photo at [`JPEG_QUALITY`] would be
/// too big to send back. See [`MAX_WATERMARKED_JPEG_BYTES`].
const FALLBACK_JPEG_QUALITIES: [u8; 6] = [90, 85, 80, 75, 70, 60];
/// Cap on the watermarked JPEG before it's signed. A Function URL response is
/// limited to 6MB *after* base64 (×4/3), and the signed photo also carries the
/// C2PA manifest with the capture as an ingredient (≈100–200KB). Re-encoding
/// a large, detailed capture at quality 95 can come out bigger than the
/// iPhone's own JPEG, and over the limit the runtime answers `413 Payload Too
/// Large` and the upload fails for good — every retry re-encodes the same
/// bytes. 4MB leaves room for both: (4MB + manifest) × 4/3 ≈ 5.6MB.
pub const MAX_WATERMARKED_JPEG_BYTES: usize = 4_000_000;

/// The artwork. Identical to the app's `BrandMarkWatermark` image set.
const BRAND_MARK_PNG: &[u8] = include_bytes!("../assets/brand-mark.png");

/// A watermarked photo, plus the mark exactly as it was placed in it.
pub struct Watermarked {
    /// The photo with the mark burned in.
    pub jpeg: Vec<u8>,
    /// The photo's claim thumbnail, made from the same pixels as
    /// [`Self::jpeg`], mark and all, before they were encoded. See
    /// `thumbnail.rs` for why it's made here rather than by c2pa.
    pub thumbnail_jpeg: Vec<u8>,
    /// The mark on its own: a transparent PNG at the size it was drawn,
    /// filled with the colour [`mark_color`] chose for this photo. It is the
    /// manifest's `c2pa.placed` ingredient, so a Content Credentials viewer
    /// pictures the mark this photo actually got — not the source artwork,
    /// which is black at 1024px whatever colour was drawn.
    pub mark_png: Vec<u8>,
    /// [`Self::mark_png`]'s thumbnail, for its own manifest: the same mark,
    /// same colour, as an opaque JPEG on the opposite colour. Supplied rather
    /// than generated — c2pa would make a transparent PNG, and a white mark
    /// on a light card would vanish. It depends on the colour alone, so it's
    /// made once per colour per Lambda instance — the only thumbnail that is.
    pub mark_thumbnail_jpeg: &'static [u8],
}

/// Longest edge of [`Watermarked::mark_thumbnail_jpeg`], and how much of it
/// the mark fills.
const MARK_THUMBNAIL_SIZE: u32 = 512;
const MARK_THUMBNAIL_FILL: f32 = 0.7;

/// A capture's pixels, upright, and the ICC profile they're in.
///
/// Decoding is its own step, apart from [`watermark`], so that one decode
/// serves everything that needs the pixels: in `/pipeline`, the original's
/// claim thumbnail and then the watermark, which also makes the photo's.
pub struct DecodedCapture {
    pub rgb: RgbImage,
    pub icc_profile: Option<Vec<u8>>,
}

/// Decodes a capture for [`watermark`].
///
/// EXIF orientation is applied to the pixels (a raw iPhone capture is almost
/// always stored sideways and tagged), so the mark lands in the corner a
/// viewer sees and the output needs no orientation tag — the same thing
/// UIKit's redraw did on device. The ICC profile is kept; other metadata
/// (EXIF, GPS) is dropped, as it was on device.
pub fn decode_capture(jpeg: &[u8]) -> Result<DecodedCapture> {
    let start = Instant::now();
    let mut decoder = ImageReader::new(Cursor::new(jpeg))
        .with_guessed_format()?
        .into_decoder()
        .context("capture is not a decodable image")?;
    let orientation = decoder.orientation()?;
    let icc_profile = decoder.icc_profile()?;
    let mut image = DynamicImage::from_decoder(decoder)?;
    image.apply_orientation(orientation);
    let rgb = image.into_rgb8();
    tracing::info!(
        step = "decode",
        width = rgb.width(),
        height = rgb.height(),
        ms = timing::ms_since(start),
        "timing"
    );
    Ok(DecodedCapture { rgb, icc_profile })
}

/// Burns the brand mark into `capture` and re-encodes it as a JPEG, carrying
/// its ICC profile over; returns that along with its claim thumbnail and the
/// mark as drawn.
pub fn watermark(capture: DecodedCapture) -> Result<Watermarked> {
    let DecodedCapture { mut rgb, icc_profile } = capture;

    // An iPhone capture is tagged Display P3; the artwork is sRGB. Pasting
    // sRGB values straight into P3 pixels would come out visibly more
    // saturated than the app's own (colour-managed) rendering of the mark.
    let is_display_p3 = icc_profile
        .as_deref()
        .is_some_and(|icc| contains(icc, b"Display P3") || contains(icc, &utf16be("Display P3")));
    let (mark_png, color) = timing::time("draw_mark", || draw_mark(&mut rgb, is_display_p3))?;

    Ok(Watermarked {
        thumbnail_jpeg: thumbnail::from_pixels("photo", &rgb, icc_profile.as_deref())?,
        jpeg: encode_within(&rgb, icc_profile.as_deref(), MAX_WATERMARKED_JPEG_BYTES)?,
        mark_png,
        mark_thumbnail_jpeg: mark_thumbnail(color)?,
    })
}

/// See [`Watermarked::mark_thumbnail_jpeg`].
fn mark_thumbnail(color: MarkColor) -> Result<&'static [u8]> {
    static BLACK: OnceLock<Vec<u8>> = OnceLock::new();
    static WHITE: OnceLock<Vec<u8>> = OnceLock::new();
    let cached = match color {
        MarkColor::Black => &BLACK,
        MarkColor::White => &WHITE,
    };
    if let Some(jpeg) = cached.get() {
        return Ok(jpeg);
    }
    let jpeg = timing::time("mark_thumbnail", || draw_mark_thumbnail(color))?;
    Ok(cached.get_or_init(|| jpeg))
}

fn draw_mark_thumbnail(color: MarkColor) -> Result<Vec<u8>> {
    let background = match color {
        MarkColor::Black => MarkColor::White,
        MarkColor::White => MarkColor::Black,
    };
    let side = MARK_THUMBNAIL_SIZE;
    let fill = image::Rgb(background.rgb().map(|v| (v * 255.0) as u8));
    let mut canvas = RgbImage::from_pixel(side, side, fill);
    let aspect = mark_aspect_ratio()?;
    let width = side as f32 * MARK_THUMBNAIL_FILL / aspect.max(1.0);
    let height = width * aspect;
    let (x, y) = ((side as f32 - width) / 2.0, (side as f32 - height) / 2.0);
    composite(&mut canvas, x, y, width, height, color.rgb())?;
    encode(&canvas, None, JPEG_QUALITY)
}

/// Encodes at [`JPEG_QUALITY`], stepping down through
/// [`FALLBACK_JPEG_QUALITIES`] only if the result is over `max_bytes`. Almost
/// every photo stays at 95; a huge, detailed one loses a little quality rather
/// than failing to upload. Returns the last attempt if even the lowest
/// quality is over — still better than a guaranteed 413.
fn encode_within(rgb: &RgbImage, icc_profile: Option<&[u8]>, max_bytes: usize) -> Result<Vec<u8>> {
    let start = Instant::now();
    let mut out = Vec::new();
    let (mut attempts, mut used) = (0, JPEG_QUALITY);
    for quality in std::iter::once(JPEG_QUALITY).chain(FALLBACK_JPEG_QUALITIES) {
        out = encode(rgb, icc_profile, quality)?;
        (attempts, used) = (attempts + 1, quality);
        if out.len() <= max_bytes {
            break;
        }
    }
    tracing::info!(
        step = "encode",
        quality = used,
        attempts,
        bytes = out.len(),
        ms = timing::ms_since(start),
        "timing"
    );
    Ok(out)
}

pub(crate) fn encode(rgb: &RgbImage, icc_profile: Option<&[u8]>, quality: u8) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut encoder = JpegEncoder::new_with_quality(&mut out, quality);
    if let Some(icc) = icc_profile {
        // Unsupported only for formats without ICC support; JPEG has it.
        let _ = encoder.set_icc_profile(icc.to_vec());
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

/// The artwork, decoded once per Lambda instance. Only its alpha channel is
/// read, so resampling it can't drag any colour into the mark's edges.
fn brand_mark() -> Result<&'static Rgba32FImage> {
    static MARK: OnceLock<Rgba32FImage> = OnceLock::new();
    if let Some(mark) = MARK.get() {
        return Ok(mark);
    }
    let mark = image::load_from_memory(BRAND_MARK_PNG)
        .context("brand-mark.png is not a decodable image")?
        .into_rgba32f();
    Ok(MARK.get_or_init(|| mark))
}

/// Which solid colour the mark is filled with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkColor {
    Black,
    White,
}

impl MarkColor {
    fn rgb(self) -> [f32; 3] {
        match self {
            MarkColor::Black => [0.0; 3],
            MarkColor::White => [1.0; 3],
        }
    }
}

/// Black on a light background, white on a dark one — see the module docs for
/// the rule, which the apps implement identically. `(x, y, width, height)` is
/// the mark's box in `image`'s pixels.
pub fn mark_color(image: &RgbImage, x: f32, y: f32, width: f32, height: f32) -> MarkColor {
    let n = COLOR_SAMPLE_GRID;
    let (max_x, max_y) = (image.width().saturating_sub(1), image.height().saturating_sub(1));
    let mut total = 0.0f32;
    for j in 0..n {
        for i in 0..n {
            let px = (x + (i as f32 + 0.5) * width / n as f32).floor().clamp(0.0, max_x as f32) as u32;
            let py = (y + (j as f32 + 0.5) * height / n as f32).floor().clamp(0.0, max_y as f32) as u32;
            let [r, g, b] = image.get_pixel(px, py).0;
            total += (0.2126 * r as f32 + 0.7152 * g as f32 + 0.0722 * b as f32) / 255.0;
        }
    }
    if total / (n * n) as f32 > LIGHT_BACKGROUND_LUMA {
        MarkColor::Black
    } else {
        MarkColor::White
    }
}

/// The artwork's height / width.
pub fn mark_aspect_ratio() -> Result<f32> {
    let mark = brand_mark()?;
    Ok(mark.height() as f32 / mark.width() as f32)
}

/// Draws the mark into `image` and returns it on its own as a PNG — see
/// [`Watermarked::mark_png`] — along with the colour it was filled with.
fn draw_mark(image: &mut RgbImage, to_display_p3: bool) -> Result<(Vec<u8>, MarkColor)> {
    let (x, y, width) = mark_placement(image.width(), image.height());
    let height = width * mark_aspect_ratio()?;
    // Decided before anything is drawn, from the photo alone.
    let chosen = mark_color(image, x, y, width, height);
    let mut color = chosen.rgb();
    if to_display_p3 {
        // A no-op for pure black and white, which are the same in both
        // spaces; kept so any future fill colour stays colour-managed.
        color = srgb_to_display_p3(color);
    }
    let scaled = composite(image, x, y, width, height, color)?;

    // The standalone PNG carries no ICC profile, so it's sRGB: the
    // pre-conversion colour (identical for black and white anyway).
    let to_u8 = |v: f32| (v.clamp(0.0, 1.0) * 255.0).round() as u8;
    let [r, g, b] = chosen.rgb().map(to_u8);
    let mark = RgbaImage::from_fn(scaled.width(), scaled.height(), |mx, my| {
        image::Rgba([r, g, b, to_u8(scaled.get_pixel(mx, my).0[3])])
    });
    let mut png = Vec::new();
    PngEncoder::new(&mut png).write_image(mark.as_raw(), mark.width(), mark.height(), ExtendedColorType::Rgba8)?;
    Ok((png, chosen))
}

/// Blends the artwork, filled with `color`, into `image` at `(x, y)` sized
/// `width`×`height`. Returns the resized artwork (its alpha is the shape).
fn composite(image: &mut RgbImage, x: f32, y: f32, width: f32, height: f32, color: [f32; 3]) -> Result<Rgba32FImage> {
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
        // Lanczos rings slightly past [0, 1].
        let alpha = px.0[3].clamp(0.0, 1.0);
        if alpha <= 0.0 {
            continue;
        }
        let dst = image.get_pixel_mut(dx as u32, dy as u32);
        for (d, s) in dst.0.iter_mut().zip(color) {
            let blended = s * alpha + (*d as f32 / 255.0) * (1.0 - alpha);
            *d = (blended * 255.0).round().clamp(0.0, 255.0) as u8;
        }
    }
    Ok(scaled)
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
    use crate::test_support::{with_exif_orientation, OFF_STROKE, ON_STROKE};
    use image::{GenericImageView, Rgb};

    fn watermark_jpeg(jpeg: &[u8]) -> Result<Watermarked> {
        watermark(decode_capture(jpeg)?)
    }

    fn gray_jpeg(width: u32, height: u32) -> Vec<u8> {
        solid_jpeg(width, height, 40)
    }

    fn solid_jpeg(width: u32, height: u32, level: u8) -> Vec<u8> {
        let img = RgbImage::from_pixel(width, height, Rgb([level; 3]));
        let mut out = Vec::new();
        JpegEncoder::new_with_quality(&mut out, 95)
            .write_image(img.as_raw(), width, height, ExtendedColorType::Rgb8)
            .unwrap();
        out
    }

    fn decode(jpeg: &[u8]) -> RgbImage {
        image::load_from_memory(jpeg).unwrap().into_rgb8()
    }

    fn is_white(p: &Rgb<u8>) -> bool {
        p.0.iter().all(|&c| c > 235)
    }

    fn is_black(p: &Rgb<u8>) -> bool {
        p.0.iter().all(|&c| c < 20)
    }

    fn at(out: &RgbImage, x: f32, y: f32, size: f32, aspect: f32, (fx, fy): (f32, f32)) -> Rgb<u8> {
        *out.get_pixel((x + size * fx) as u32, (y + size * aspect * fy) as u32)
    }

    #[test]
    fn mark_lands_top_trailing_and_nowhere_else() {
        let out = decode(&watermark_jpeg(&gray_jpeg(1000, 800)).unwrap().jpeg);
        assert_eq!(out.dimensions(), (1000, 800));

        let (x, y, size) = mark_placement(1000, 800);
        assert_eq!((x, y, size), (1000.0 - 72.0 - 28.0, 28.0, 72.0));
        let aspect = mark_aspect_ratio().unwrap();
        assert!(is_white(&at(&out, x, y, size, aspect, ON_STROKE)), "dark photo, white mark");
        assert!(!is_white(&at(&out, x, y, size, aspect, OFF_STROKE)), "the spiral's gaps stay photo");
        // Other corners untouched.
        for (px, py) in [(10, 10), (10, 790), (990, 790)] {
            assert!(!is_white(out.get_pixel(px, py)));
        }
    }

    #[test]
    fn the_mark_is_black_on_a_light_photo_and_white_on_a_dark_one() {
        let (x, y, size) = mark_placement(1000, 800);
        let aspect = mark_aspect_ratio().unwrap();
        let light = decode(&watermark_jpeg(&solid_jpeg(1000, 800, 230)).unwrap().jpeg);
        assert!(is_black(&at(&light, x, y, size, aspect, ON_STROKE)));
        let dark = decode(&watermark_jpeg(&solid_jpeg(1000, 800, 25)).unwrap().jpeg);
        assert!(is_white(&at(&dark, x, y, size, aspect, ON_STROKE)));
    }

    /// Only the box the mark covers decides — not the rest of the photo.
    #[test]
    fn colour_is_decided_by_the_area_under_the_mark() {
        let mut img = RgbImage::from_pixel(1000, 800, Rgb([20; 3]));
        let (x, y, size) = mark_placement(1000, 800);
        let h = size * mark_aspect_ratio().unwrap();
        for py in y as u32..(y + h).ceil() as u32 {
            for px in x as u32..(x + size).ceil() as u32 {
                img.put_pixel(px, py, Rgb([240; 3]));
            }
        }
        assert_eq!(mark_color(&img, x, y, size, h), MarkColor::Black);
        assert_eq!(mark_color(&RgbImage::from_pixel(1000, 800, Rgb([240; 3])), x, y, size, h), MarkColor::Black);
        assert_eq!(mark_color(&RgbImage::from_pixel(1000, 800, Rgb([20; 3])), x, y, size, h), MarkColor::White);
    }

    /// Pins the threshold the apps mirror: mid-grey (luma exactly 0.5 sits
    /// just under 128/255) gets white; one step brighter, black.
    #[test]
    fn the_threshold_is_half_luma() {
        let (x, y, size) = (0.0, 0.0, 64.0);
        assert_eq!(mark_color(&RgbImage::from_pixel(64, 64, Rgb([127; 3])), x, y, size, size), MarkColor::White);
        assert_eq!(mark_color(&RgbImage::from_pixel(64, 64, Rgb([128; 3])), x, y, size, size), MarkColor::Black);
        // Luma, not a plain average: pure green reads light, pure blue dark.
        assert_eq!(mark_color(&RgbImage::from_pixel(64, 64, Rgb([0, 255, 0])), x, y, size, size), MarkColor::Black);
        assert_eq!(mark_color(&RgbImage::from_pixel(64, 64, Rgb([0, 0, 255])), x, y, size, size), MarkColor::White);
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
        let landscape = gray_jpeg(1200, 900);
        let tagged = with_exif_orientation(&landscape, 6);
        let out = decode(&watermark_jpeg(&tagged).unwrap().jpeg);
        assert_eq!(out.dimensions(), (900, 1200), "output should be the upright portrait");

        let (x, y, size) = mark_placement(900, 1200);
        let aspect = mark_aspect_ratio().unwrap();
        assert!(is_white(&at(&out, x, y, size, aspect, ON_STROKE)));
    }

    /// Display P3 shares sRGB's white point and transfer curve: greys,
    /// including the mark's black and white, convert to themselves.
    #[test]
    fn greys_are_unchanged_by_the_display_p3_conversion() {
        for v in [0.0, 0.5, 1.0] {
            let p3 = srgb_to_display_p3([v; 3]);
            assert!(p3.iter().all(|c| (c - v).abs() < 0.002), "{p3:?}");
        }
        // A saturated colour does move: pure sRGB red sits inside P3.
        let red = srgb_to_display_p3([1.0, 0.0, 0.0]);
        assert!(red[0] < 0.95 && red[1] > 0.1, "{red:?}");
    }

    /// Must be the same PNG as the iOS `BrandMarkWatermark` image set and
    /// Android's `brand_mark_watermark` — `CapturePipelineTests` and
    /// `PhotoWatermarkerTest` pin the same dimensions. When the artwork
    /// changes, replace it in all three repos and update all three tests.
    #[test]
    fn artwork_is_the_shared_png_and_large_enough_for_a_48mp_capture() {
        let mark = brand_mark().unwrap();
        assert_eq!(mark.dimensions(), (1024, 1082));
        assert!(mark.width() >= 544, "a 48MP capture's mark is 544px wide");
    }

    /// Pseudo-random noise: the worst case for JPEG, like a big, detailed photo.
    fn noise(width: u32, height: u32) -> RgbImage {
        let mut state = 0x2545_f491_u32;
        RgbImage::from_fn(width, height, |_, _| {
            let mut px = [0u8; 3];
            for c in &mut px {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                *c = state as u8;
            }
            Rgb(px)
        })
    }

    #[test]
    fn a_photo_that_fits_stays_at_full_quality() {
        let img = noise(200, 200);
        let full = encode(&img, None, JPEG_QUALITY).unwrap();
        assert_eq!(encode_within(&img, None, full.len()).unwrap(), full);
    }

    /// Over the cap, quality steps down until it fits — rather than sending
    /// a response the Lambda runtime refuses with a 413.
    #[test]
    fn a_photo_over_the_cap_is_re_encoded_smaller() {
        let img = noise(400, 400);
        let full = encode(&img, None, JPEG_QUALITY).unwrap();
        let cap = full.len() * 3 / 4;
        let capped = encode_within(&img, None, cap).unwrap();
        assert!(capped.len() <= cap, "{} > {cap}", capped.len());
        assert_eq!(image::load_from_memory(&capped).unwrap().dimensions(), (400, 400));
    }

    /// The cap leaves room for base64 and the manifest under the 6MB limit.
    #[test]
    fn the_cap_fits_the_function_url_limit_with_room_for_the_manifest() {
        let with_manifest = MAX_WATERMARKED_JPEG_BYTES + 300_000;
        assert!(with_manifest.div_ceil(3) * 4 < 6 * 1024 * 1024);
    }

    /// The standalone mark is what was drawn: the placed size, and the
    /// chosen colour — white over a dark photo, black over a light one.
    #[test]
    fn the_mark_png_is_the_mark_as_drawn() {
        let (_, _, size) = mark_placement(1000, 800);
        let aspect = mark_aspect_ratio().unwrap();
        for (level, expected) in [(25u8, 255u8), (230, 0)] {
            let png = watermark_jpeg(&solid_jpeg(1000, 800, level)).unwrap().mark_png;
            let mark = image::load_from_memory(&png).unwrap().into_rgba8();
            assert_eq!(mark.width(), size.round() as u32);
            let on = mark.get_pixel((size * ON_STROKE.0) as u32, (size * aspect * ON_STROKE.1) as u32);
            assert_eq!(on.0, [expected, expected, expected, 255], "level {level}");
            let off = mark.get_pixel((size * OFF_STROKE.0) as u32, (size * aspect * OFF_STROKE.1) as u32);
            assert!(off.0[3] < 8, "level {level}: {off:?}"); // Lanczos ringing
        }
    }

    /// The thumbnail shows the drawn colour on the opposite one.
    #[test]
    fn the_mark_thumbnail_is_the_drawn_colour_on_its_opposite() {
        let aspect = mark_aspect_ratio().unwrap();
        let side = MARK_THUMBNAIL_SIZE as f32;
        let w = side * MARK_THUMBNAIL_FILL / aspect.max(1.0);
        let (x, y) = ((side - w) / 2.0, (side - w * aspect) / 2.0);
        for (level, mark, background) in [(25u8, 255u8, 0u8), (230, 0, 255)] {
            let thumb = decode(watermark_jpeg(&solid_jpeg(1000, 800, level)).unwrap().mark_thumbnail_jpeg);
            assert_eq!(thumb.dimensions(), (MARK_THUMBNAIL_SIZE, MARK_THUMBNAIL_SIZE));
            let corner = thumb.get_pixel(2, 2).0;
            assert!(corner.iter().all(|&c| c.abs_diff(background) < 20), "level {level}: {corner:?}");
            let on = at(&thumb, x, y, w, aspect, ON_STROKE).0;
            assert!(on.iter().all(|&c| c.abs_diff(mark) < 20), "level {level}: {on:?}");
        }
    }

    /// The one thumbnail made once and kept: per colour, since nothing else
    /// about the photo changes it.
    #[test]
    fn the_mark_thumbnail_is_made_once_per_colour() {
        let dark = || watermark_jpeg(&solid_jpeg(400, 300, 25)).unwrap().mark_thumbnail_jpeg;
        let light = watermark_jpeg(&solid_jpeg(400, 300, 230)).unwrap().mark_thumbnail_jpeg;
        assert!(std::ptr::eq(dark(), dark()));
        assert_ne!(dark(), light);
    }

    #[test]
    fn non_images_are_rejected() {
        assert!(watermark_jpeg(b"definitely not a jpeg").is_err());
    }
}

