use dirs;
use env_logger;
use goblin::{elf::Elf, pe::PE};
use hex;
use log::{error, info, warn};
use sha2::{Digest, Sha256};
use std::env;
use std::fs;

mod detectors;
mod engines;
mod models;
mod utils;

use detectors::decoder::b64_decode_strings;
use detectors::network::network_iocs;
use detectors::plain::hunt_plaintext_threats;
use engines::arrays::hunt_shift_obfuscation;
use engines::obfuscation::{hunt_stateful_obfuscation, hunt_strreverse_obfuscation};
use models::ScanResult;
use utils::file::{FileCategory, identify_file};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let app_name = env!("CARGO_PKG_NAME");
    let base_path = dirs::data_local_dir()
        .ok_or("Can't find local data directory")?
        .join(app_name);

    let evidence_dir = base_path.join("evidences");
    fs::create_dir_all(&evidence_dir)?;

    let args: Vec<String> = env::args().collect();
    let target = args.get(1).ok_or("Use: kovacs <file_path>")?;
    let pwd = env::current_dir()?;
    let artifact_path = pwd.join(target);
    let buffer = fs::read(&artifact_path)?;

    // Fingerprint
    let mut hasher = Sha256::new();
    hasher.update(&buffer);
    let hash_string = hex::encode(hasher.finalize());
    let hash_result = hash_string.to_string();

    let file_category = identify_file(&artifact_path)?;

    let mut results = ScanResult::new();
    let evidence_path = evidence_dir.join(format!("{}.evidence", hash_result));

    match file_category {
        FileCategory::ExecutablePE => {
            if let Ok(pe) = PE::parse(&buffer) {
                info!("    Format: Windows PE");
                info!("     - Sections:");
                for section in &pe.sections {
                    info!(
                        "    - {} (Flags: {}, Address: {:#x}, Offset: {:#x}, Size: {:#x})",
                        section.real_name.clone().unwrap_or("Unknown".to_string()),
                        section.characteristics,
                        section.virtual_address,
                        section.pointer_to_raw_data,
                        section.size_of_raw_data
                    );
                }
                for import in &pe.imports {
                    let dll = import.dll;
                    if dll.contains("wininet") || dll.contains("advapi32") {
                        warn!("[!] Alert: {}", import.name);
                        warn!("[!] Suspicious DLL: {}", dll);
                    }
                }
            } else {
                error!("Failed to parse PE");
            }
        }
        FileCategory::ExecutableELF => {
            if let Ok(elf) = Elf::parse(&buffer) {
                info!("    Format: Linux ELF");
                info!("     - Sections:");
                for section in &elf.section_headers {
                    info!(
                        "    - {} (Type: {}, Flags: {:#x}, Address: {:#x}, Offset: {:#x}, Size: {:#x})",
                        section.sh_name,
                        section.sh_type,
                        section.sh_flags,
                        section.sh_addr,
                        section.sh_offset,
                        section.sh_size
                    );
                }
            } else {
                error!("Failed to parse ELF");
            }
        }
        FileCategory::Script => {
            let content = String::from_utf8_lossy(&buffer);
            let b64_decode_strings = b64_decode_strings(&content);
            results.base64_strings.extend(b64_decode_strings);

            let plaintext_iocs = hunt_plaintext_threats(&content);
            results.plaintext_iocs.extend(plaintext_iocs);

            let strreverse_obfuscation = hunt_strreverse_obfuscation(&content);
            results.script_obfuscation.extend(strreverse_obfuscation);

            let stateful_obfuscation = hunt_stateful_obfuscation(&content);
            results.stateful_obfuscation.extend(stateful_obfuscation);

            let array_obfuscation = hunt_shift_obfuscation(&content);
            results.shifted_array_strings.extend(array_obfuscation);

            // network IOCs for all fields decoded and desobfuscated
            for (_, decoded) in &results.base64_strings {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }
            for (_, decoded) in &results.reversed_strings {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }
            for (_, decoded) in &results.script_obfuscation {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }
            for (_, decoded) in &results.stateful_obfuscation {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }
            for decoded in &results.shifted_array_strings {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }
            for decoded in &results.plaintext_iocs {
                let is_netowork_ioc = network_iocs(decoded);
                if is_netowork_ioc.0.len() > 0 || is_netowork_ioc.1.len() > 0 {
                    results.ips.extend(is_netowork_ioc.1.clone());
                    results.urls.extend(is_netowork_ioc.0.clone());
                }
            }

            // Output Plaintext result and save evidence
            results.print_report();
            results.save_evidence_json(&evidence_path.with_extension("json"))?;
            results.save_evidence_md(&evidence_path.with_extension("md"))?;
            info!("Evidence saved: {:?}", evidence_path.with_extension("json"));
        }
        FileCategory::Unknown => {}
    }

    println!("Evidence saved: {:?} (json, md)", evidence_path);
    Ok(())
}
