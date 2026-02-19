use encoding_rs::{EUC_KR, SHIFT_JIS};

/// Decode filename bytes with the given flags and raw data.
/// flags bit 4: 0=UTF-8, 1=area code (locale-specific)
/// If area code, locale_code selects encoding: 932=Shift-JIS, 949=EUC-KR, 0=system default.
pub fn decode_filename(flags: u8, locale_code: Option<u16>, data: &[u8]) -> String {
    let use_area_code = flags & 0x10 != 0;

    if !use_area_code {
        // UTF-8
        return String::from_utf8_lossy(data).into_owned();
    }

    let locale = locale_code.unwrap_or(0);
    let encoding = match locale {
        932 => SHIFT_JIS,
        949 | 0 => EUC_KR,
        _ => EUC_KR,
    };

    let (decoded, _, _) = encoding.decode(data);
    decoded.into_owned()
}

/// Normalize path separators to forward slash and strip leading slashes.
pub fn normalize_path(path: &str) -> String {
    path.replace('\\', "/").trim_start_matches('/').to_string()
}
