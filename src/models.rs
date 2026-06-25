use log::info;
use serde::Serialize;
use std::path::Path;

#[derive(Serialize, Clone, Debug)]
pub struct ScanResult {
    pub urls: Vec<String>,
    pub ips: Vec<String>,

    // (Original, Descoded)
    pub base64_strings: Vec<(String, String)>,
    pub reversed_strings: Vec<(String, String)>,
    pub script_obfuscation: Vec<(String, String)>,
    pub stateful_obfuscation: Vec<(String, String)>,

    pub shifted_array_strings: Vec<String>,
    pub plaintext_iocs: Vec<String>,
}

impl ScanResult {
    pub fn new() -> Self {
        ScanResult {
            urls: Vec::new(),
            ips: Vec::new(),
            base64_strings: Vec::new(),
            reversed_strings: Vec::new(),
            script_obfuscation: Vec::new(),
            stateful_obfuscation: Vec::new(),
            shifted_array_strings: Vec::new(),
            plaintext_iocs: Vec::new(),
        }
    }

    pub fn report(&self) -> String {
        let mut evidence = String::from("# --- [ KOVACS EVIDENCES ] ---\n");

        if !self.ips.is_empty() {
            evidence.push_str("\n## [ NETWORK IOCs ] ---");
            for ip in &self.ips {
                evidence.push_str(&format!("\nIP: {}", ip));
            }
        }
        if !self.urls.is_empty() {
            evidence.push_str("\n## [ URL IOCs ]");
            for url in &self.urls {
                evidence.push_str(&format!("\nURL: {}", url));
            }
        }

        if !self.base64_strings.is_empty() {
            evidence.push_str("\n## [ DECODED BASE64 ]");
            for (orig, dec) in &self.base64_strings {
                evidence.push_str(&format!("\nOriginal: {}\n↳ Decoded: {}", orig, dec));
            }
        }

        if !self.reversed_strings.is_empty() {
            evidence.push_str("\n## [ OBFUSCATION DETECTED (StrReverse) ]");
            for (orig, dec) in &self.reversed_strings {
                evidence.push_str(&format!("\nOriginal: {}\n↳ Reversed: {}", orig, dec));
            }
        }

        if !self.shifted_array_strings.is_empty() {
            evidence.push_str("\n## [ OBFUSCATION DETECTED (Array Math) ]");
            for arr in &self.shifted_array_strings {
                evidence.push_str(&format!("\nArray Shift Decoded: {:?}", arr));
            }
        }

        if !self.plaintext_iocs.is_empty() {
            evidence.push_str("\n## [ PLAINTEXT THREAT SCAN ]");
            for str in &self.plaintext_iocs {
                evidence.push_str(&format!("\nPlaintext IOC Detected: {}", str));
            }
        }

        return evidence;
    }

    pub fn print_report(&self) {
        info!("{}", self.report());
    }

    pub fn save_evidence_json(&self, path: &Path) -> std::io::Result<()> {
        let json_output = serde_json::to_string_pretty(&self)?;
        std::fs::write(path, json_output)
    }

    pub fn save_evidence_md(&self, path: &Path) -> std::io::Result<()> {
        let txt_output = self.report();
        std::fs::write(path, txt_output)
    }
}
