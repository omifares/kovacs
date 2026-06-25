use std::{fs::File, io::Read, path::Path};

#[derive(Debug, PartialEq)]
pub enum FileCategory {
    ExecutablePE,
    ExecutableELF,
    Script,
    Unknown,
}

pub fn identify_file<P: AsRef<Path>>(path: P) -> Result<FileCategory, std::io::Error> {
    let mut file = File::open(path)?;
    let mut buffer = [0; 4];

    if file.read(&mut buffer)? < 4 {
        return Ok(FileCategory::Unknown);
    }

    match buffer {
        [0x4D, 0x5A, ..] => Ok(FileCategory::ExecutablePE), // MZ - Windows PE
        [0x7F, 0x45, 0x4C, 0x46] => Ok(FileCategory::ExecutableELF), // ELF - Linux
        _ => Ok(FileCategory::Script),
    }
}
