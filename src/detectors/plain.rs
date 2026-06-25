use log::info;
use std::collections::HashSet;

use crate::utils::treat_detection::is_threat;

pub fn hunt_plaintext_threats(content: &str) -> Vec<String> {
    let mut seen_threats = HashSet::new();
    let mut plaintext_iocs = Vec::new();

    for line in content.lines() {
        let clean_line = line.trim();

        if is_threat(clean_line) && seen_threats.insert(clean_line.to_string()) {
            info!("[!] Plaintext IOC Detected: {clean_line}");
            plaintext_iocs.push(clean_line.to_string());
        }
    }

    plaintext_iocs
}
