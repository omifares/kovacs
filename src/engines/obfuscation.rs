use log::info;
use regex::Regex;
use std::collections::HashMap;

use crate::utils::treat_detection::is_threat;

// (?i) - Case-insensitive
// (\w+) - Var name
// \s*=\s* - Equals sign
// "([^"]+)" - String obfuscated
// [\s\S]{1,200}? - Limit to 200 chars
// StrReverse\(\1\) - StrReverse with a backreference to the variable name
pub fn hunt_strreverse_obfuscation(content: &str) -> Vec<(String, String)> {
    let reverse_pattern =
        Regex::new(r#"(?i)(\w+)\s*=\s*"([^"]+)"[\s\S]{1,200}?StrReverse\((\w+)\)"#).unwrap();
    let mut results = Vec::new();

    for cap in reverse_pattern.captures_iter(content) {
        let var_decl = &cap[1];
        let original_obfuscated = &cap[2];
        let var_reversed = &cap[3];

        if var_decl == var_reversed {
            let decoded: String = original_obfuscated.chars().rev().collect();

            if is_threat(&decoded) {
                println!("[!] StrReverse Threat: {}", decoded);
                results.push((var_decl.to_string(), decoded));
            }
        }
    }
    results
}

// Memory to storage var and strings definition
pub fn hunt_stateful_obfuscation(content: &str) -> Vec<(String, String)> {
    let mut memory: HashMap<String, String> = HashMap::new();
    let mut results = Vec::new();

    let assignment_regex = Regex::new(r"(?i)([a-z_][a-z0-9_]*)\s*=\s*(.+)").unwrap();
    let string_literal_regex = Regex::new(r#""([^"]*)""#).unwrap();

    // Chr(119)
    let chr_regex = Regex::new(r"(?i)chr\s*\(\s*(\d+)\s*\)").unwrap();

    for chunk in content.split(['\n', '\r', ':']) {
        let clean_chunk = chunk.trim();
        if clean_chunk.is_empty() {
            continue;
        }

        if let Some(cap) = assignment_regex.captures(clean_chunk) {
            let var_name = cap[1].to_lowercase();
            let expression = &cap[2];

            let mut resolved_value = String::new();

            // Concat
            let parts: Vec<&str> = expression.split(['&', '+']).collect();

            for part in parts {
                let part_trimmed = part.trim();

                if part_trimmed.starts_with('"') && part_trimmed.ends_with('"') {
                    if let Some(str_cap) = string_literal_regex.captures(part_trimmed) {
                        resolved_value.push_str(&str_cap[1]);
                    } else if let Some(chr_cap) = chr_regex.captures(part_trimmed)
                        && let Ok(ascii_num) = chr_cap[1].parse::<u8>()
                    {
                        resolved_value.push(ascii_num as char);
                    }
                } else {
                    let var_key = part_trimmed.to_lowercase();
                    if let Some(known_value) = memory.get(&var_key) {
                        resolved_value.push_str(known_value);
                    }
                }
            }

            if !resolved_value.is_empty() {
                memory.insert(var_name.clone(), resolved_value.clone());

                if !resolved_value.is_empty() {
                    memory.insert(var_name.clone(), resolved_value.clone());

                    if is_threat(&resolved_value) {
                        info!("\n--- [ OBFUSCATION DETECTED (Stateful) ] ---");
                        info!("    ↳ Variable: {}", var_name);
                        info!("    ↳ Payload:  {}", resolved_value);
                        info!("[!] Resolved Concatenation!");

                        results.push((var_name, resolved_value));
                    }
                }
            }
        }
    }

    results
}
