use log::info;
use regex::Regex;

pub fn network_iocs(content: &str) -> (Vec<String>, Vec<String>) {
    let url_regex = Regex::new(r"(?i)https?://[^\\s/$.?#].[^\\s]*").unwrap();
    let ip_regex = Regex::new(r"(?i)\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b").unwrap();
    let mut urls = Vec::new();
    let mut ips = Vec::new();

    for url in url_regex.find_iter(content) {
        let found_url = url.as_str().to_string();
        info!("[!] URL Detected: {}", found_url);
        if !urls.contains(&found_url) {
            urls.push(found_url);
        }
    }

    for ip in ip_regex.find_iter(content) {
        let found_ip = ip.as_str().to_string();
        info!("[!] IP Detected: {}", found_ip);
        if !ips.contains(&found_ip) {
            ips.push(found_ip);
        }
    }

    (urls, ips)
}
