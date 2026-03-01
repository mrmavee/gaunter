//! File signature validation.
//!
//! Provides magic number detection to identify safe MIME types for uploads.

/// Detects MIME types for safe uploads.
#[must_use]
pub fn detect_safe_mime(data: &[u8]) -> Option<&'static str> {
    if data.len() < 3 {
        return None;
    }

    if data.starts_with(b"%PDF-") {
        return Some("application/pdf");
    }

    if data.starts_with(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) {
        return Some("image/png");
    }

    if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }

    if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        return Some("image/gif");
    }

    if data.len() >= 12 && data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WEBP") {
        return Some("image/webp");
    }

    if data.len() >= 12
        && data.get(4..8) == Some(b"ftyp")
        && (data.get(8..12) == Some(b"avif") || data.get(8..12) == Some(b"avis"))
    {
        return Some("image/avif");
    }

    if data.len() >= 12 && data.get(4..8) == Some(b"ftyp") {
        let subtype = data.get(8..12);
        if subtype == Some(b"isom")
            || subtype == Some(b"mp41")
            || subtype == Some(b"mp42")
            || subtype == Some(b"qt  ")
        {
            return Some("video/mp4");
        }
    }

    if data.starts_with(b"ID3") {
        return Some("audio/mpeg");
    }

    if data.len() >= 12 && data.starts_with(b"RIFF") && data.get(8..12) == Some(b"WAVE") {
        return Some("audio/wav");
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mime_detection() {
        assert_eq!(detect_safe_mime(b"%PDF-1.7"), Some("application/pdf"));

        assert_eq!(
            detect_safe_mime(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
            Some("image/png")
        );

        assert_eq!(
            detect_safe_mime(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some("image/jpeg")
        );

        assert_eq!(detect_safe_mime(b"GIF87a"), Some("image/gif"));
        assert_eq!(detect_safe_mime(b"GIF89a"), Some("image/gif"));

        assert_eq!(
            detect_safe_mime(b"RIFF\x00\x00\x00\x00WEBP"),
            Some("image/webp")
        );

        assert_eq!(
            detect_safe_mime(b"\x00\x00\x00\x00ftypavif"),
            Some("image/avif")
        );

        assert_eq!(
            detect_safe_mime(b"\x00\x00\x00\x00ftypavis"),
            Some("image/avif")
        );

        assert_eq!(
            detect_safe_mime(b"\x00\x00\x00\x00ftypisom"),
            Some("video/mp4")
        );

        assert_eq!(detect_safe_mime(b"ID3\x04\x00"), Some("audio/mpeg"));

        assert_eq!(
            detect_safe_mime(b"RIFF\x00\x00\x00\x00WAVE"),
            Some("audio/wav")
        );

        assert_eq!(detect_safe_mime(b""), None);
        assert_eq!(detect_safe_mime(b"AB"), None);
        assert_eq!(detect_safe_mime(b"\x00\x00\x00\x00\x00\x00\x00\x00"), None);
        assert_eq!(detect_safe_mime(b"NOT_A_FORMAT_AT_ALL"), None);

        assert_eq!(detect_safe_mime(b"GIF8"), None);
        assert_eq!(detect_safe_mime(&[0x89, 0x50, 0x4E]), None);
    }
}
