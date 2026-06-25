static SUSPICIOUS_KEYWORDS: &[&str] = &[
    // --- NETWORK & DOWNLOADERS ---
    "http",
    "xmlhttp",
    "msxml2.xmlhttp",
    "winhttprequest",
    "system.net.webclient",
    "bitsadmin",
    "certutil",
    // --- EXECUTION & LOLBINS ---
    "wscript",
    "powershell",
    "cmd.exe",
    "shell",
    "exec",
    "execute",
    "eval",
    "mshta",
    "rundll32",
    "regsvr32",
    "createobject",
    "getobject",
    "invoke",
    // --- RECON ---
    "winmgmts",
    "select *",
    "root\\\\cimv2",
    "wmic",
    "win32_process",
    "win32_computersystem",
    // --- DROPPERS ---
    "scripting.filesystemobject",
    "adodb.stream",
    "savetofile",
    // --- PERSISTENCE ---
    "schtasks",
    "regwrite",
    "wscript.network",
    "expandenvironmentstrings",
    "%userprofile%",
    "%appdata%",
    "%temp%",
    "%public%",
    "startup",
    "edgeupdate",
    // --- EVASION ---
    "isdebuggerpresent",
    "wscript.sleep",
];

pub fn is_threat(text: &str) -> bool {
    if text.len() < 5 {
        return false;
    }
    let text_lower = text.to_lowercase();
    SUSPICIOUS_KEYWORDS.iter().any(|&k| text_lower.contains(k))
}
