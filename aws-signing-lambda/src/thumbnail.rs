//! Claim thumbnails, made from pixels this Lambda already has in memory.
//!
//! A C2PA claim thumbnail (C2PA 2.2 §18.13) is an optional, approximate
//! picture of the asset at claim time: at most one per manifest, in whatever
//! format the claim generator chooses. Validators check its hash, never its
//! pixels against the asset's. It is what the Content Credentials viewer
//! pictures a manifest by, and an ingredient by too, through that
//! ingredient's own manifest's claim thumbnail (§18.13.1.2). Without one the
//! card is blank.
//!
//! c2pa-rs can make one itself (its `add_thumbnails` feature): a
//! `Builder::sign` with no `thumbnail` in its definition decodes the whole
//! JPEG it's signing, applies EXIF orientation, downscales and re-encodes.
//! That is ~110ms per 12MP capture on an M1 core and more on the Lambda's
//! single vCPU, for pixels this Lambda had just decoded
//! anyway to draw the mark. So every manifest here supplies its thumbnail:
//! [`from_pixels`] for the original and the photo, built from the decoded
//! capture; [`from_jpeg_scaled`] for `/capture`, which otherwise never
//! decodes; and the brand mark's own (`watermark::Watermarked`).
//!
//! The output matches c2pa's defaults (`ThumbnailSettings::default()`): JPEG
//! at quality 75 (`ThumbnailQuality::Medium`), 1024px on the long edge,
//! upright, downscaled with the same `imageops::thumbnail`. There are two
//! differences. A picture smaller than that is kept at its own size rather
//! than enlarged. And the capture's ICC profile is embedded (Display P3 for an
//! iPhone, about 0.5KB), so the thumbnail shows the photo's colours. c2pa's
//! thumbnail has no profile, so a viewer reads its P3 values as sRGB and
//! shows them duller.
//!
//! Each thumbnail is made from its own asset's pixels at the moment it's
//! signed, and never cached: only the brand mark's is (it's the same for
//! every photo given the colour).

use anyhow::{anyhow, bail, Context, Result};
use image::{imageops, metadata::Orientation, DynamicImage, GrayImage, RgbImage};
use std::io::Cursor;
use std::time::Instant;

use crate::{timing, watermark};

/// Long edge of every thumbnail made here. c2pa's default `long_edge`.
pub const LONG_EDGE: u32 = 1024;
/// JPEG quality. What c2pa encodes `ThumbnailQuality::Medium`, its default, as.
pub const QUALITY: u8 = 75;
/// The media type every thumbnail made here has.
pub const FORMAT: &str = "image/jpeg";
/// [`from_jpeg_scaled`] decodes at the smallest DCT scale (1/8, 1/4, 1/2)
/// whose long edge is at least this, so the thumbnail lands between this and
/// [`LONG_EDGE`]: a 12MP iPhone capture (4032px) decodes at 1/4, to 1008px,
/// a 48MP one at 1/8.
const MIN_SCALED_LONG_EDGE: u16 = 768;

/// A thumbnail of `rgb`, which must already be upright. `asset` names it in
/// the timing log.
pub fn from_pixels(asset: &'static str, rgb: &RgbImage, icc_profile: Option<&[u8]>) -> Result<Vec<u8>> {
    let start = Instant::now();
    let jpeg = encode(rgb, icc_profile)?;
    let (width, height) = fit(rgb.width(), rgb.height());
    tracing::info!(step = "thumbnail", asset, from = "pixels", width, height, ms = timing::ms_since(start), "timing");
    Ok(jpeg)
}

/// A thumbnail of a capture nothing else needs decoded (`/capture`): the
/// JPEG decoded at reduced scale, which skips most of the IDCT and colour
/// conversion of a full decode and leaves only a small image to rotate.
/// EXIF orientation is applied and the ICC profile kept, as for
/// [`from_pixels`].
///
/// Errs on what this decoder can't read (CMYK, 16-bit), where the caller
/// leaves the thumbnail to c2pa.
pub fn from_jpeg_scaled(jpeg: &[u8]) -> Result<Vec<u8>> {
    let start = Instant::now();
    // jpeg-decoder panics on a few malformed frame headers rather than
    // erroring; these are untrusted bytes, and a failure only means the
    // caller falls back to c2pa's thumbnail.
    let (mut image, icc_profile, orientation) =
        std::panic::catch_unwind(|| decode_scaled(jpeg)).map_err(|_| anyhow!("the JPEG decoder panicked"))??;
    let (decoded_width, decoded_height) = (image.width(), image.height());
    image.apply_orientation(orientation);
    let jpeg = encode(&image.into_rgb8(), icc_profile.as_deref())?;
    tracing::info!(
        step = "thumbnail",
        asset = "capture",
        from = "scaled_decode",
        decoded_width,
        decoded_height,
        ms = timing::ms_since(start),
        "timing"
    );
    Ok(jpeg)
}

fn decode_scaled(jpeg: &[u8]) -> Result<(DynamicImage, Option<Vec<u8>>, Orientation)> {
    let mut decoder = jpeg_decoder::Decoder::new(Cursor::new(jpeg));
    let (width, height) = decoder.scale(MIN_SCALED_LONG_EDGE, MIN_SCALED_LONG_EDGE)?;
    let pixels = decoder.decode()?;
    let (width, height) = (u32::from(width), u32::from(height));
    let image = match decoder.info().context("decoded without a frame header")?.pixel_format {
        jpeg_decoder::PixelFormat::RGB24 => RgbImage::from_raw(width, height, pixels).map(DynamicImage::ImageRgb8),
        jpeg_decoder::PixelFormat::L8 => GrayImage::from_raw(width, height, pixels).map(DynamicImage::ImageLuma8),
        other => bail!("{other:?} JPEGs aren't supported here"),
    }
    .context("decoded pixels don't match the frame size")?;
    let orientation = decoder
        .exif_data()
        .and_then(Orientation::from_exif_chunk)
        .unwrap_or(Orientation::NoTransforms);
    Ok((image, decoder.icc_profile(), orientation))
}

/// Downscales to [`fit`] and encodes.
fn encode(rgb: &RgbImage, icc_profile: Option<&[u8]>) -> Result<Vec<u8>> {
    let (width, height) = fit(rgb.width(), rgb.height());
    if (width, height) == rgb.dimensions() {
        return watermark::encode(rgb, icc_profile, QUALITY);
    }
    watermark::encode(&imageops::thumbnail(rgb, width, height), icc_profile, QUALITY)
}

/// A thumbnail's size: [`LONG_EDGE`] on the long edge, the aspect ratio kept
/// (rounded as c2pa rounds it), or the picture's own size if it's smaller.
fn fit(width: u32, height: u32) -> (u32, u32) {
    let long_edge = width.max(height);
    if long_edge <= LONG_EDGE {
        return (width, height);
    }
    let ratio = f64::from(LONG_EDGE) / f64::from(long_edge);
    let scaled = |side: u32| ((f64::from(side) * ratio).round() as u32).max(1);
    (scaled(width), scaled(height))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{assert_red_on_top_blue_below, jpeg, two_tone, with_exif_orientation, TEST_ICC};

    fn decode(jpeg: &[u8]) -> (RgbImage, Option<Vec<u8>>) {
        use image::ImageDecoder;
        let mut decoder = image::codecs::jpeg::JpegDecoder::new(Cursor::new(jpeg)).unwrap();
        let icc = decoder.icc_profile().unwrap();
        (DynamicImage::from_decoder(decoder).unwrap().into_rgb8(), icc)
    }

    #[test]
    fn fits_the_long_edge_to_1024_and_never_enlarges() {
        assert_eq!(fit(4032, 3024), (1024, 768));
        assert_eq!(fit(3024, 4032), (768, 1024));
        assert_eq!(fit(8064, 6048), (1024, 768));
        assert_eq!(fit(5712, 4284), (1024, 768));
        assert_eq!(fit(4000, 1800), (1024, 461));
        assert_eq!(fit(1024, 700), (1024, 700));
        assert_eq!(fit(640, 480), (640, 480));
        assert_eq!(fit(100_000, 10), (1024, 1));
    }

    #[test]
    fn matches_c2pas_defaults() {
        let defaults = c2pa::settings::Settings::default().builder.thumbnail;
        assert_eq!(defaults.long_edge, LONG_EDGE);
        assert_eq!(defaults.quality, c2pa::settings::builder::ThumbnailQuality::Medium);
        assert!(defaults.enabled, "c2pa's own thumbnails stay on, as the fallback");
    }

    #[test]
    fn a_thumbnail_from_pixels_is_a_1024px_jpeg_with_the_captures_profile() {
        let thumbnail = from_pixels("capture", &two_tone(2048, 1536), Some(TEST_ICC)).unwrap();
        let (rgb, icc) = decode(&thumbnail);
        assert_eq!(rgb.dimensions(), (1024, 768));
        assert_eq!(icc.as_deref(), Some(TEST_ICC));

        let (small, icc) = decode(&from_pixels("capture", &two_tone(640, 480), None).unwrap());
        assert_eq!(small.dimensions(), (640, 480), "never enlarged");
        assert_eq!(icc, None);
    }

    /// A 12MP-like capture decodes at 1/4 scale: 800px is what a 1/4-scale
    /// decode of 3200px gives, where downscaling a full decode would give
    /// 1024px.
    #[test]
    fn a_scaled_thumbnail_decodes_at_a_fraction_of_full_size() {
        let (rgb, icc) = decode(&from_jpeg_scaled(&jpeg(&two_tone(3200, 2400), Some(TEST_ICC))).unwrap());
        assert_eq!(rgb.dimensions(), (800, 600));
        assert_eq!(icc.as_deref(), Some(TEST_ICC));
        // Too big at the first scale that reaches 768px (1/2: 1200px), so
        // downscaled from there.
        let (rgb, _) = decode(&from_jpeg_scaled(&jpeg(&two_tone(2400, 1800), None)).unwrap());
        assert_eq!(rgb.dimensions(), (1024, 768));
        // Already small: decoded at full size, kept at that size.
        let (rgb, _) = decode(&from_jpeg_scaled(&jpeg(&two_tone(640, 480), None)).unwrap());
        assert_eq!(rgb.dimensions(), (640, 480));
    }

    /// Orientation 6 (rotate 90° clockwise to view), as an iPhone stores a
    /// portrait: the stored left half becomes the top.
    #[test]
    fn a_scaled_thumbnail_is_upright() {
        let tagged = with_exif_orientation(&jpeg(&two_tone(3200, 2400), None), 6);
        let (rgb, _) = decode(&from_jpeg_scaled(&tagged).unwrap());
        assert_eq!(rgb.dimensions(), (600, 800));
        assert_red_on_top_blue_below(&rgb);
    }

    #[test]
    fn a_thumbnail_of_pixels_keeps_them_upright() {
        let rgb = DynamicImage::ImageRgb8(two_tone(1200, 900)).rotate90().into_rgb8();
        let (thumbnail, _) = decode(&from_pixels("photo", &rgb, None).unwrap());
        assert_eq!(thumbnail.dimensions(), (768, 1024));
        assert_red_on_top_blue_below(&thumbnail);
    }

    #[test]
    fn a_scaled_thumbnail_of_a_non_jpeg_errs() {
        assert!(from_jpeg_scaled(b"definitely not a jpeg").is_err());
        assert!(from_jpeg_scaled(&[0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08]).is_err());
    }
}
