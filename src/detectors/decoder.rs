use base64::{Engine, prelude::BASE64_STANDARD};
use log::info;
use regex::Regex;

pub fn b64_decode_strings(content: &str) -> Vec<(String, String)> {
    let b64_regex = Regex::new(r"[a-zA-Z0-9+/]{8,}=*").unwrap();
    let mut results = Vec::new();

    for cap in b64_regex.captures_iter(content) {
        let candidate = &cap[0];

        if let Ok(decoded_bytes) = BASE64_STANDARD.decode(candidate) {
            let decoded_string = String::from_utf8_lossy(&decoded_bytes);
            let is_printable = decoded_bytes
                .iter()
                .all(|&b| (32..=126).contains(&b) || b == 10 || b == 13);

            if decoded_string.chars().any(|c| c.is_alphanumeric())
                && decoded_string.len() > 4
                && is_printable
            {
                let trimmed_string = decoded_string.trim().to_string();

                info!("[!] Base64 Detected: {}", candidate);
                info!("    ↳ Decoded: {}", trimmed_string);

                results.push((candidate.to_string(), trimmed_string.clone()));
            }
        }
    }

    results
}
