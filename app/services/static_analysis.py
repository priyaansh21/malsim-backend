"""
services/static_analysis.py — Static file analysis engine.

Performs:
  1. Hash computation (MD5 / SHA1 / SHA256)
  2. Entropy analysis (packing / obfuscation detection)
  3. Suspicious string extraction (API calls, registry keys, commands)
  4. Signature database matching (simulated YARA-style)
  5. File type / section metadata extraction
  
NOTE: This is a high-fidelity *simulation* — no real malware is executed.
      All signatures and strings are matched against known-bad keyword lists.
"""

import asyncio
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.config import settings
from app.utils.file_handler import compute_hashes, compute_entropy, entropy_label, human_readable_size
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE — Suspicious indicators (real-world educated simulation)
# ═══════════════════════════════════════════════════════════════════════════════

CRITICAL_INDICATORS = [
    ("cmd.exe /c powershell.exe -EncodedCommand", "CMD", "CRITICAL"),
    ("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "REG", "CRITICAL"),
    ("VirtualAllocEx", "API", "CRITICAL"),
    ("WriteProcessMemory", "API", "CRITICAL"),
    ("ShellExecuteEx", "API", "CRITICAL"),
    ("NtUnmapViewOfSection", "API", "CRITICAL"),
    ("SetWindowsHookEx", "API", "CRITICAL"),
]

HIGH_INDICATORS = [
    ("CreateRemoteThread", "API", "HIGH"),
    ("OpenProcess", "API", "HIGH"),
    ("NtSetInformationThread", "API", "HIGH"),
    ("IsDebuggerPresent", "API", "HIGH"),
    ("CheckRemoteDebuggerPresent", "API", "HIGH"),
    ("ZwQueryInformationProcess", "API", "HIGH"),
    ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "REG", "HIGH"),
    ("C:\\Windows\\Temp", "STR", "HIGH"),
    ("powershell -enc", "CMD", "HIGH"),
    ("net user /add", "CMD", "HIGH"),
    ("reg add HKLM", "CMD", "HIGH"),
]

MEDIUM_INDICATORS = [
    ("GetSystemDirectoryA", "API", "MED"),
    ("LoadLibraryA", "API", "MED"),
    ("GetProcAddress", "API", "MED"),
    ("InternetOpenA", "API", "MED"),
    ("HttpSendRequestA", "API", "MED"),
    ("WSAStartup", "API", "MED"),
    ("connect", "NET", "MED"),
    ("gethostbyname", "NET", "MED"),
]

LOW_INDICATORS = [
    ("GetModuleHandleA", "API", "LOW"),
    ("FindFirstFileA", "API", "LOW"),
    ("CreateFileA", "API", "LOW"),
    ("ReadFile", "API", "LOW"),
    ("GetTempPathA", "STR", "LOW"),
]

# Signature database (SIG-ID → name, weight)
SIGNATURE_DATABASE = [
    ("SIG-001", "Trojan.Generic.Dropper",         28),
    ("SIG-014", "Trojan.Inject.ProcessHollow",    26),
    ("SIG-022", "Malware.Persistence.RunKey",      22),
    ("SIG-035", "Packer.UPX.Obfuscated",           18),
    ("SIG-041", "AntiDebug.IsDebuggerPresent",     15),
    ("SIG-007", "Ransomware.FileEncryptor",        30),
    ("SIG-019", "Worm.NetworkPropagator",          20),
    ("SIG-055", "Backdoor.ReverseTCP",             25),
    ("SIG-062", "Spyware.KeyloggerHook",           22),
    ("SIG-078", "Dropper.MacroEmbedded",           18),
]

# Extension → expected file-type description
FILE_TYPE_MAP = {
    ".exe": "PE32 executable (GUI) Intel 80386",
    ".dll": "PE32 DLL Intel 80386",
    ".ps1": "ASCII text, PowerShell script",
    ".bat": "DOS batch file, ASCII text",
    ".vbs": "Visual Basic Script, ASCII text",
    ".js":  "JavaScript source, ASCII text",
    ".pdf": "PDF document, version 1.7",
    ".doc": "Composite Document File (MS Office)",
    ".docx": "Microsoft Word OOXML document",
    ".zip": "Zip archive data",
    ".bin": "data (binary, high entropy)",
    ".sh":  "POSIX shell script, ASCII text",
    ".apk": "Android APK (ZIP archive)",
}

# Extension → section list for PE files
PE_SECTIONS = {
    ".exe": ".text, .data, .rsrc, .upx0, .upx1 — UPX packed",
    ".dll": ".text, .data, .rdata, .reloc",
}


# ═══════════════════════════════════════════════════════════════════════════════
# SIMULATION PROFILES per sample name (deterministic for demo files)
# ═══════════════════════════════════════════════════════════════════════════════

SAMPLE_PROFILES: dict[str, dict] = {
    "trojan_dropper_sim.exe": {
        "sig_hits": {"SIG-001", "SIG-014", "SIG-022", "SIG-035", "SIG-041"},
        "critical_count": 4, "high_count": 4, "med_count": 3,
        "entropy": 7.82, "packer": "UPX",
        "compile_time": "2024-03-15 14:22:08 UTC",
    },
    "keylogger_hook.dll": {
        "sig_hits": {"SIG-062", "SIG-041", "SIG-022"},
        "critical_count": 2, "high_count": 3, "med_count": 4,
        "entropy": 6.45, "packer": None,
        "compile_time": "2024-01-09 08:11:34 UTC",
    },
    "persistence_script.ps1": {
        "sig_hits": {"SIG-022", "SIG-041"},
        "critical_count": 3, "high_count": 3, "med_count": 2,
        "entropy": 4.12, "packer": None,
        "compile_time": "N/A (script file)",
    },
    "ransomware_stub.bin": {
        "sig_hits": {"SIG-007", "SIG-035", "SIG-022"},
        "critical_count": 5, "high_count": 4, "med_count": 2,
        "entropy": 7.94, "packer": "custom",
        "compile_time": "2023-11-22 03:47:19 UTC",
    },
    "resume_clean.pdf": {
        "sig_hits": set(),
        "critical_count": 0, "high_count": 0, "med_count": 1,
        "entropy": 3.12, "packer": None,
        "compile_time": "N/A (document)",
    },
    "spyware_macro.doc": {
        "sig_hits": {"SIG-078", "SIG-062"},
        "critical_count": 2, "high_count": 2, "med_count": 3,
        "entropy": 5.61, "packer": None,
        "compile_time": "N/A (document)",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

async def run_static_analysis(
    file_bytes: bytes,
    original_name: str,
    file_id: str,
    extension: str,
    md5: str,
    sha1: str,
    sha256: str,
) -> dict[str, Any]:
    """
    Perform full static analysis and return a structured result dict.

    Execution flow:
      step 1: validate & retrieve profile
      step 2: build hash_metadata block
      step 3: extract suspicious strings (deterministic per profile)
      step 4: run signature database matching
      step 5: compile and return
    """
    logger.info("[%s] Starting static analysis for '%s'", file_id, original_name)

    # ── Step 0: Profile lookup ─────────────────────────────────────────────────
    profile = SAMPLE_PROFILES.get(original_name.lower())

    # ── Step 1: Entropy ────────────────────────────────────────────────────────
    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    if profile:
        entropy = profile["entropy"]
        packer  = profile["packer"]
    else:
        entropy = compute_entropy(file_bytes) if len(file_bytes) > 0 else random.uniform(3.0, 7.9)
        packer  = "UPX" if entropy > 7.5 else None

    ent_label = entropy_label(entropy)

    # ── Step 2: Hash metadata ─────────────────────────────────────────────────
    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    file_type   = FILE_TYPE_MAP.get(extension, f"Unknown ({extension})")
    sections    = PE_SECTIONS.get(extension, "N/A (non-PE file)")
    size_str    = human_readable_size(len(file_bytes))
    compile_ts  = profile["compile_time"] if profile else "Unknown"

    hash_metadata = {
        "filename":     original_name,
        "md5":          md5,
        "sha1":         sha1,
        "sha256":       sha256,
        "file_size":    size_str,
        "file_type":    file_type,
        "entropy":      entropy,
        "entropy_label": ent_label,
        "compile_time": compile_ts,
        "sections":     sections,
        "packer":       packer,
    }

    # ── Step 3: String extraction ──────────────────────────────────────────────
    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    suspicious_strings = _extract_strings(profile, file_bytes)

    # ── Step 4: Signature matching ─────────────────────────────────────────────
    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    sig_hits  = profile["sig_hits"] if profile else set()
    signatures = [
        {
            "sig_id": sig_id,
            "name": name,
            "matched": sig_id in sig_hits,
        }
        for sig_id, name, _ in SIGNATURE_DATABASE
    ]

    # ── Static score sub-component ─────────────────────────────────────────────
    crit_score = len([s for s in suspicious_strings if s["severity"] == "CRITICAL"]) * 12
    high_score = len([s for s in suspicious_strings if s["severity"] == "HIGH"]) * 7
    ent_bonus  = 15 if entropy >= 7.5 else (8 if entropy >= 6.0 else 0)
    sig_score  = len(sig_hits) * 15
    static_score = min(crit_score + high_score + ent_bonus + sig_score, 100)

    alert = None
    matched_count = len(sig_hits)
    if matched_count > 0:
        alert = (
            f"SUSPICIOUS FILE — {matched_count} signature(s) matched. "
            f"Multiple malware indicators found in static analysis."
        )

    logger.info(
        "[%s] Static analysis complete: entropy=%.2f, sigs=%d, score=%.0f",
        file_id, entropy, matched_count, static_score,
    )

    return {
        "hash_metadata":      hash_metadata,
        "suspicious_strings": suspicious_strings,
        "signature_matches":  signatures,
        "static_score":       round(static_score, 2),
        "alert":              alert,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

import re

def _extract_strings(profile: dict | None, file_bytes: bytes) -> list[dict]:
    """
    Extract real ASCII strings from binary (length >= 5).
    Matches against known suspicious keywords for scoring.
    Merges with profile simulation hits if applicable for demo purposes.
    """
    strings = []
    
    # 1. Real extraction
    # Regex finds sequences of printable ASCII characters of length >= 5
    ascii_pattern = re.compile(b"[\x20-\x7E]{5,}")
    found_bytes = ascii_pattern.findall(file_bytes)
    
    extracted_text = []
    for b in found_bytes:
        try:
            txt = b.decode("ascii")
            extracted_text.append(txt)
        except Exception:
            pass
            
    # Remove duplicates but keep some order
    seen = set()
    unique_text = []
    for txt in extracted_text:
        if txt not in seen:
            seen.add(txt)
            unique_text.append(txt)

    # 2. Keyword detection rules
    # We map keywords to their (Category, Severity)
    keywords = {
        "cmd.exe": ("CMD", "HIGH"),
        "powershell": ("CMD", "CRITICAL"),
        "VirtualAlloc": ("API", "CRITICAL"),
        "WriteProcessMemory": ("API", "CRITICAL"),
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run": ("REG", "CRITICAL"),
        "CreateRemoteThread": ("API", "HIGH"),
        "IsDebuggerPresent": ("API", "HIGH"),
        "LoadLibraryA": ("API", "MED"),
        "GetProcAddress": ("API", "MED"),
        "http://": ("NET", "MED"),
        "https://": ("NET", "MED"),
    }

    for txt in unique_text:
        is_suspicious = False
        for kw, (cat, sev) in keywords.items():
            if kw.lower() in txt.lower():
                strings.append({"severity": sev, "value": txt, "category": cat})
                is_suspicious = True
                break
        
        # Optionally, keep a few benign strings if the list is empty (for LOW severity)
        if not is_suspicious and len(strings) < 20 and len(txt) < 50:
            strings.append({"severity": "LOW", "value": txt, "category": "STR"})

    # 3. If file is very small or it's a simulation profile without real payload (e.g. dummy exe),
    # we inject the simulated strings to ensure the demo works beautifully.
    if profile:
        taken_crit = random.sample(CRITICAL_INDICATORS, min(profile["critical_count"], len(CRITICAL_INDICATORS)))
        taken_high = random.sample(HIGH_INDICATORS,     min(profile["high_count"],     len(HIGH_INDICATORS)))
        taken_med  = random.sample(MEDIUM_INDICATORS,   min(profile["med_count"],      len(MEDIUM_INDICATORS)))
        taken_low  = random.sample(LOW_INDICATORS,      1)
        
        for value, category, severity in taken_crit + taken_high + taken_med + taken_low:
            # Avoid direct duplicates
            if not any(s["value"] == value for s in strings):
                strings.append({"severity": severity, "value": value, "category": category})

    # Sort strings so CRITICAL is at the top
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MED": 2, "LOW": 3}
    strings.sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    # Cap to avoid massive payloads crashing the UI
    return strings[:100]
