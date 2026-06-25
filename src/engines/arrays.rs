use log::info;
use regex::Regex;

use crate::utils::treat_detection::is_threat;

pub fn hunt_shift_obfuscation(content: &str) -> Vec<String> {
    let array_regex = Regex::new(r"(?i)Array\s*\(([^)]+)\)").unwrap();
    let mut extracted_arrays: Vec<Vec<i32>> = Vec::new();
    let mut shifted_array_strings: Vec<String> = Vec::new();

    for cap in array_regex.captures_iter(content) {
        let inner_content = &cap[1];
        let mut numbers = Vec::new();

        for part in inner_content.split(',') {
            let clean_part = part.trim().to_uppercase().replace("&H", "");

            if let Ok(num) = i32::from_str_radix(&clean_part, 16) {
                numbers.push(num);
            } else if let Ok(num) = clean_part.parse::<i32>() {
                numbers.push(num);
            }
        }

        if numbers.len() >= 5 {
            extracted_arrays.push(numbers);
        }
    }

    for i in 0..extracted_arrays.len() {
        if i + 1 < extracted_arrays.len() {
            let arr1 = &extracted_arrays[i];
            let arr2 = &extracted_arrays[i + 1];

            let mut shifted_str = String::new();
            let min_len = arr1.len().min(arr2.len());

            for j in 0..min_len {
                let val = arr1[j] + arr2[j];

                if (32..=126).contains(&val) {
                    shifted_str.push(val as u8 as char);
                }
            }

            if is_threat(&shifted_str) {
                info!("\n--- [ OBFUSCATION DETECTED (Array Math) ] ---");
                info!("[!] Array Shift Decoded: {}", shifted_str);

                shifted_array_strings.push(shifted_str);
            }
        }
    }

    shifted_array_strings
}
