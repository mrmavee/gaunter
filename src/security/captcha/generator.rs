//! CAPTCHA image generation.
//!
//! Implements visual noise, character rotation, and coordinate-based validation.

use ab_glyph::{FontRef, PxScale};
use base64::{Engine, engine::general_purpose::STANDARD};
use image::{ImageBuffer, Rgb, RgbImage};
use imageproc::drawing::{draw_antialiased_line_segment_mut, draw_text_mut};
use imageproc::geometric_transformations::{Interpolation, rotate_about_center};
use imageproc::pixelops::interpolate;
use rand::prelude::{IndexedMutRandom, IndexedRandom};
use rand::{Rng, RngExt};
use std::time::{SystemTime, UNIX_EPOCH};

const CHARSET: &[u8] = b"ACDEFGHJKLMNPQRSTUVWXYZ2345679";
const IMG_SIZE_U32: u32 = 160;
const IMG_SIZE_F32: f32 = 160.0;
const PASSCODE_LENGTH: usize = 6;
const FONT_BYTES: &[u8] = include_bytes!("../../../assets/Hack-Bold.ttf");

pub struct CharPosition {
    pub x: f32,
    pub y: f32,
    pub rotation: f32,
}

type CharMapItem = (String, f32, f32, f32);

struct CharDrawParams {
    ch: char,
    x: f32,
    y: f32,
    size: f32,
    rotation_deg: f32,
    color: Rgb<u8>,
}

struct ArcParams {
    cx: i32,
    cy: i32,
    radius: i32,
    start_deg: f32,
    sweep_deg: f32,
    color: Rgb<u8>,
}

/// CAPTCHA difficulty levels.
#[derive(Clone, Copy)]
pub enum Difficulty {
    /// Easy.
    Easy,
    /// Medium.
    Medium,
    /// Hard.
    Hard,
}

impl std::str::FromStr for Difficulty {
    type Err = ();

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "easy" => Ok(Self::Easy),
            "hard" => Ok(Self::Hard),
            _ => Ok(Self::Medium),
        }
    }
}

impl Difficulty {
    const fn decoy_count(self) -> usize {
        match self {
            Self::Easy => 40,
            Self::Medium => 60,
            Self::Hard => 80,
        }
    }

    const fn arc_count(self) -> usize {
        match self {
            Self::Easy => 20,
            Self::Medium => 30,
            Self::Hard => 40,
        }
    }
}

use crate::error::{Error, Result};
use crate::security::crypto::CookieCrypto;

/// CAPTCHA image generator handling drawing logic.
pub struct CaptchaGenerator {
    cookie_crypto: CookieCrypto,
    ttl_secs: u64,
    difficulty: Difficulty,
    font: FontRef<'static>,
}

impl CaptchaGenerator {
    /// Initializes a new generator instance.
    ///
    /// # Errors
    /// Returns error if generator initialization fails.
    pub fn try_new(secret: &str, ttl_secs: u64, difficulty: Difficulty) -> Result<Self> {
        let font = FontRef::try_from_slice(FONT_BYTES)
            .map_err(|_| Error::Captcha("Failed to load embedded font".to_string()))?;
        Ok(Self {
            cookie_crypto: CookieCrypto::new(secret),
            ttl_secs,
            difficulty,
            font,
        })
    }

    /// Generates a new CAPTCHA.
    ///
    /// # Errors
    /// Returns error if generation fails.
    pub fn generate(&self) -> Result<(String, String, Vec<CharPosition>)> {
        let mut rng = rand::rng();

        let (width, height) = (IMG_SIZE_U32, IMG_SIZE_U32);

        let mut img: RgbImage = ImageBuffer::from_fn(width, height, |_, _| Rgb([26, 30, 35]));

        let (colors, line_colors) = Self::generate_colors(&mut rng);

        Self::draw_background(&mut img, &mut rng, self.difficulty, &colors, &line_colors);
        self.draw_decoys(&mut img, &mut rng, &line_colors)?;

        let (final_passcode, positions) = {
            let (char_map, font_size) = self.draw_main_chars(&mut img, &mut rng, &colors)?;
            Self::select_passcode(&mut rng, char_map, font_size)
        };

        let mut webp_data = Vec::with_capacity(4096);
        img.write_to(
            &mut std::io::Cursor::new(&mut webp_data),
            image::ImageFormat::WebP,
        )?;

        let img_base64 = format!("data:image/webp;base64,{}", STANDARD.encode(&webp_data));

        Ok((final_passcode, img_base64, positions))
    }

    /// Creates a signed validation token.
    ///
    /// # Errors
    /// Returns error if token signing fails.
    pub fn create_token(&self, passcode: &str) -> Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Captcha("SystemTime error".to_string()))?
            .as_secs();
        let expiry = now + self.ttl_secs;
        let payload = format!("{passcode}|{expiry}");
        self.cookie_crypto.try_encrypt(payload.as_bytes())
    }

    fn draw_rotated_char(
        &self,
        img: &mut RgbImage,
        params: &CharDrawParams,
        offsets: &[(f32, f32)],
    ) {
        let scratch_size = f32_to_u32(params.size * 2.0);
        let mut scratch: RgbImage =
            ImageBuffer::from_pixel(scratch_size, scratch_size, Rgb([26, 30, 35]));

        let center_offset = i32::try_from(scratch_size / 4).unwrap_or(0);
        draw_text_mut(
            &mut scratch,
            params.color,
            center_offset,
            center_offset,
            PxScale::from(params.size),
            &self.font,
            &params.ch.to_string(),
        );

        let angle_rad = params.rotation_deg.to_radians();
        let rotated = rotate_about_center(
            &scratch,
            angle_rad,
            Interpolation::Bilinear,
            Rgb([26, 30, 35]),
        );

        let half_scratch = i32::try_from(scratch_size / 2).unwrap_or(0);
        let params_x = params.x;
        let params_y = params.y;

        let (width, height) = img.dimensions();
        let width_i32 = i32::try_from(width).unwrap_or(160);
        let height_i32 = i32::try_from(height).unwrap_or(160);

        for (rx, ry, pixel) in rotated.enumerate_pixels() {
            if pixel[0] > 30 || pixel[1] > 35 || pixel[2] > 40 {
                let pixel_x = i32::try_from(rx).unwrap_or(0);
                let pixel_y = i32::try_from(ry).unwrap_or(0);

                for &(off_x, off_y) in offsets {
                    let gx = f32_to_i32(params_x + off_x) + pixel_x - half_scratch;
                    let gy = f32_to_i32(params_y + off_y) + pixel_y - half_scratch;

                    if (0..width_i32).contains(&gx)
                        && (0..height_i32).contains(&gy)
                        && let (Ok(gx_u32), Ok(gy_u32)) = (u32::try_from(gx), u32::try_from(gy))
                    {
                        img.put_pixel(gx_u32, gy_u32, *pixel);
                    }
                }
            }
        }
    }

    fn draw_arc(img: &mut RgbImage, params: &ArcParams) {
        let steps: i16 = 50;
        let start_rad = params.start_deg.to_radians();
        let sweep_rad = params.sweep_deg.to_radians();

        let radius_f32 = f32::from(i16::try_from(params.radius).unwrap_or(0));
        let mut prev_x = params.cx + f32_to_i32(radius_f32 * start_rad.cos());
        let mut prev_y = params.cy + f32_to_i32(radius_f32 * start_rad.sin());

        for i in 1..=steps {
            let i_f32 = f32::from(i);
            let steps_f32 = f32::from(steps);
            let angle = start_rad + (sweep_rad * i_f32 / steps_f32);
            let curr_x = params.cx + f32_to_i32(radius_f32 * angle.cos());
            let curr_y = params.cy + f32_to_i32(radius_f32 * angle.sin());

            if prev_x >= 0 && prev_y >= 0 && curr_x >= 0 && curr_y >= 0 {
                draw_antialiased_line_segment_mut(
                    img,
                    (prev_x, prev_y),
                    (curr_x, curr_y),
                    params.color,
                    interpolate,
                );
            }

            prev_x = curr_x;
            prev_y = curr_y;
        }
    }

    /// Verifies token integrity.
    #[must_use]
    pub fn verify(&self, token: &str, answer: &str) -> bool {
        let Ok(decrypted) = self.cookie_crypto.decrypt(token).ok_or(()) else {
            return false;
        };
        let Ok(payload) = String::from_utf8(decrypted) else {
            return false;
        };

        let parts: Vec<&str> = payload.split('|').collect();
        let [expected_passcode, expiry_str] = parts.as_slice() else {
            return false;
        };

        let Ok(expiry) = expiry_str.parse::<u64>() else {
            return false;
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if now > expiry {
            return false;
        }

        (*expected_passcode) == answer.to_uppercase().replace([' ', '\n'], "")
    }

    fn generate_colors(rng: &mut impl Rng) -> (Vec<Rgb<u8>>, Vec<Rgb<u8>>) {
        let mut colors: Vec<Rgb<u8>> = Vec::new();
        for _ in 0..4 {
            let mut c = [
                rng.random_range(90..=255),
                rng.random_range(90..=255),
                rng.random_range(90..=255),
            ];
            if let Some(val) = c.choose_mut(rng) {
                *val = rng.random_range(180..=255);
            }
            colors.push(Rgb(c));
        }
        let line_colors: Vec<Rgb<u8>> = colors.iter().take(2).copied().collect();
        (colors, line_colors)
    }

    fn draw_background(
        img: &mut RgbImage,
        rng: &mut impl Rng,
        difficulty: Difficulty,
        colors: &[Rgb<u8>],
        line_colors: &[Rgb<u8>],
    ) {
        let (width, height) = img.dimensions();
        let width_i32 = i32::try_from(width).unwrap_or(160);
        let height_i32 = i32::try_from(height).unwrap_or(160);

        for _ in 0..difficulty.arc_count() {
            let color = if rng.random_range(0..100) < 25 {
                *colors.choose(rng).unwrap_or(&Rgb([0, 0, 0]))
            } else {
                *line_colors.choose(rng).unwrap_or(&Rgb([0, 0, 0]))
            };

            let arc = ArcParams {
                cx: rng.random_range(0..width_i32),
                cy: rng.random_range(0..height_i32),
                radius: rng.random_range(10..80),
                start_deg: rng.random_range(0.0..360.0_f32),
                sweep_deg: rng.random_range(30.0..180.0_f32),
                color,
            };
            Self::draw_arc(img, &arc);
        }
    }

    fn draw_decoys(
        &self,
        img: &mut RgbImage,
        rng: &mut impl Rng,
        line_colors: &[Rgb<u8>],
    ) -> Result<()> {
        let (width, height) = img.dimensions();
        let width_f32 = f32::from(u16::try_from(width).unwrap_or(160));
        let height_f32 = f32::from(u16::try_from(height).unwrap_or(160));

        let fake_font_size = rng.random_range(16.0..28.0);
        for _ in 0..self.difficulty.decoy_count() {
            let params = CharDrawParams {
                ch: *CHARSET
                    .choose(rng)
                    .ok_or_else(|| Error::Captcha("Charset empty".to_string()))?
                    as char,
                x: rng.random_range(5.0..(width_f32 - 20.0)),
                y: rng.random_range(5.0..(height_f32 - 20.0)),
                size: fake_font_size,
                rotation_deg: rng.random_range(0.0..360.0),
                color: *line_colors
                    .choose(rng)
                    .ok_or_else(|| Error::Captcha("Line colors empty".to_string()))?,
            };
            self.draw_rotated_char(img, &params, &[(0.0, 0.0)]);
        }
        Ok(())
    }

    fn draw_main_chars(
        &self,
        img: &mut RgbImage,
        rng: &mut impl Rng,
        colors: &[Rgb<u8>],
    ) -> Result<(Vec<CharMapItem>, f32)> {
        let font_size: f32 = rng.random_range(20.0..26.0);
        let mut char_map: Vec<CharMapItem> = Vec::new();

        let step = font_size.mul_add(1.3, 4.0);
        let max_pos = font_size.mul_add(-1.5, IMG_SIZE_F32);
        for col in 0..20_u16 {
            let col_f32 = f32::from(col);
            let x_base = col_f32.mul_add(step, 4.0);
            if x_base >= max_pos {
                break;
            }

            let x_pos = x_base + rng.random_range(0.0..4.0);

            for row in 0..20_u16 {
                let row_f32 = f32::from(row);

                let y_base = row_f32 * font_size * 1.3;
                if y_base >= max_pos {
                    break;
                }

                let y_pos = y_base + rng.random_range(4.0..12.0);

                let ch = *CHARSET
                    .choose(rng)
                    .ok_or_else(|| Error::Captcha("Charset empty".to_string()))?
                    as char;
                let x_buffer = x_pos + rng.random_range(-2.0..6.0);
                let rotation = rng.random_range(0.0..60.0);
                let color = *colors
                    .choose(rng)
                    .ok_or_else(|| Error::Captcha("Colors empty".to_string()))?;

                let params = CharDrawParams {
                    ch,
                    x: x_buffer,
                    y: y_pos,
                    size: font_size,
                    rotation_deg: rotation,
                    color,
                };
                self.draw_rotated_char(img, &params, &[(0.0, 0.0), (1.0, 0.0)]);

                char_map.push((ch.to_string(), x_buffer, y_pos, rotation));
            }
        }
        Ok((char_map, font_size))
    }

    fn select_passcode(
        rng: &mut impl Rng,
        char_map: Vec<CharMapItem>,
        font_size: f32,
    ) -> (String, Vec<CharPosition>) {
        let mut final_passcode = String::new();
        let mut positions = Vec::new();
        let margin = 20.0;
        let safe_chars: Vec<_> = char_map
            .into_iter()
            .filter(|(_, x, y, _)| {
                *x >= margin
                    && *x <= (IMG_SIZE_F32 - margin)
                    && *y >= margin
                    && *y <= (IMG_SIZE_F32 - margin)
            })
            .collect();

        let mut available_chars = safe_chars;

        for _ in 0..PASSCODE_LENGTH {
            if available_chars.is_empty() {
                break;
            }
            let idx = rng.random_range(0..available_chars.len());
            let (text, mut x, mut y, rot) = available_chars.remove(idx);
            final_passcode.push_str(&text);

            x -= (9.0 - font_size).mul_add(1.1, font_size);
            y -= (13.0 - font_size).mul_add(1.1, font_size);
            x = x.max(0.0);
            y = y.max(0.0);

            positions.push(CharPosition {
                x,
                y,
                rotation: rot,
            });
        }
        (final_passcode, positions)
    }
}

#[inline]
#[allow(clippy::cast_possible_truncation)]
fn f32_to_i32(val: f32) -> i32 {
    let clamped = val.round().clamp(f32::from(i16::MIN), f32::from(i16::MAX));
    clamped as i32
}

#[inline]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn f32_to_u32(val: f32) -> u32 {
    let clamped = val.round().clamp(0.0, f32::from(u16::MAX));
    clamped as u32
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn captcha_token_lifecycle() {
        let generator = CaptchaGenerator::try_new("secret-key", 300, Difficulty::Medium).unwrap();

        let token = generator.create_token("CAPTCHA").unwrap();
        assert!(generator.verify(&token, "CAPTCHA"));
        assert!(generator.verify(&token, "captcha"));
        assert!(generator.verify(&token, "C A P T C H A"));
        assert!(!generator.verify(&token, "INVALID"));
        assert!(!generator.verify(&token, ""));

        assert!(!generator.verify("invalid-token-format", "CAPTCHA"));
        assert!(!generator.verify("", "CAPTCHA"));

        let mut tampered = token;
        tampered.push('X');
        assert!(!generator.verify(&tampered, "CAPTCHA"));

        let g = CaptchaGenerator::try_new("alt-secret", 300, Difficulty::Easy).unwrap();
        let tok = g.create_token("PASSED").unwrap();
        assert!(g.verify(&tok, "PASSED"));
        assert!(!g.verify(&tok, "FAILED"));

        let g = CaptchaGenerator::try_new("hard-secret", 300, Difficulty::Hard).unwrap();
        let (passcode, img, positions) = g.generate().unwrap();
        assert!(!passcode.is_empty());
        assert!(img.starts_with("data:image/webp;base64,"));
        assert!(!positions.is_empty());
        let tok = g.create_token(&passcode).unwrap();
        assert!(g.verify(&tok, &passcode));
    }
}
