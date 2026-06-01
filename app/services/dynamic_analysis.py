"""
services/dynamic_analysis.py — Sandboxed behavior simulation engine.

Simulates what would happen if the file ran inside an isolated environment:
  - Process creation & injection tree
  - File system mutations (create, write, modify, delete)
  - Registry modifications (persistence, AV disable)
  - Network connections (C2 beacon, DNS, HTTP exfiltration)
  - Real-time timestamped behavior event log

No real code execution ever takes place.
"""

import asyncio
import random
from typing import Any

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# BEHAVIOR TEMPLATES per sample profile
# ═══════════════════════════════════════════════════════════════════════════════

_PROFILES: dict[str, dict] = {
    "trojan_dropper_sim.exe": {
        "process_tree": [
            {"pid": 1234, "name": "explorer.exe",            "parent_pid": None, "label": "NORMAL"},
            {"pid": 5812, "name": "trojan_dropper_sim.exe",  "parent_pid": 1234, "label": "SUSPICIOUS"},
            {"pid": 6001, "name": "cmd.exe",                 "parent_pid": 5812, "label": "INJECTED"},
            {"pid": 6042, "name": "powershell.exe",          "parent_pid": 6001, "label": "MALICIOUS"},
            {"pid": 6100, "name": "svchost.exe",             "parent_pid": 5812, "label": "HOLLOWED"},
        ],
        "resource_usage": {"cpu_pct": 73, "memory_mb": 512, "network_label": "C2 beacon", "disk_io_label": "High"},
        "behavior_log": [
            ("PROC",  "PID 5812: trojan_dropper_sim.exe — Process created by explorer.exe"),
            ("PROC",  "PID 5812: OpenProcess(PROCESS_ALL_ACCESS) targeting PID 1234 (lsass.exe)"),
            ("PROC",  "PID 5812: VirtualAllocEx in remote process — RWX memory allocated 0x4096 bytes"),
            ("PROC",  "PID 5812: WriteProcessMemory — shellcode injected to PID 1234"),
            ("FILE",  "Created: C:\\Users\\victim\\AppData\\Roaming\\svch0st.exe (dropped payload)"),
            ("REG",   "HKLM\\...\\CurrentVersion\\Run → \"SvcUpdate\" key created for persistence"),
            ("NET",   "DNS query: update.windowsservice.cc → 92.223.89.12 (fast-flux domain)"),
            ("NET",   "TCP SYN → 185.220.101.47:4444 — C2 beacon established"),
            ("ALERT", "⚠ ALERT: IsDebuggerPresent() called — anti-analysis evasion detected"),
            ("FILE",  "Modified: C:\\Windows\\System32\\drivers\\etc\\hosts — DNS poisoning attempt"),
            ("REG",   "HKLM\\SYSTEM\\...\\WinDefend → Start=4 — Defender disabled via registry"),
            ("NET",   "HTTP POST /upload.php → 185.220.101.47 — Possible data exfiltration"),
            ("PROC",  "PID 6001: cmd.exe spawned by PID 5812 — encoded PowerShell execution"),
            ("ALERT", "⚠ ALERT: Process hollowing detected — svchost.exe memory overwritten"),
        ],
        "fs_changes": [
            {"operation": "WRITE",  "path": "C:\\Users\\victim\\AppData\\Roaming\\svch0st.exe",   "detail": "Dropped secondary payload (32 KB)"},
            {"operation": "CREATE", "path": "C:\\Windows\\Temp\\~tmp_4f2a.bat",                    "detail": "Created batch script for persistence setup"},
            {"operation": "MODIFY", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",          "detail": "Added malicious DNS redirect entries"},
            {"operation": "DELETE", "path": "C:\\Users\\victim\\Desktop\\important_docs\\",        "detail": "Mass file deletion/encryption preparation"},
            {"operation": "WRITE",  "path": "C:\\ProgramData\\Microsoft\\update.dll",              "detail": "Disguised persistence DLL injection"},
        ],
        "reg_changes": [
            {"operation": "SET",    "key": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SvcUpdate",  "detail": "= \"C:\\ProgramData\\Microsoft\\update.dll\""},
            {"operation": "SET",    "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Explorer",   "detail": "= \"C:\\Users\\victim\\AppData\\svch0st.exe\""},
            {"operation": "MODIFY", "key": "HKLM\\System\\CurrentControlSet\\Services\\WinDefend",                "detail": "Disabled Windows Defender service"},
            {"operation": "CREATE", "key": "HKCU\\Software\\MalwareKey\\config",                                  "detail": "Encrypted C2 configuration stored in registry"},
            {"operation": "MODIFY", "key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options", "detail": "Debugger hijack"},
        ],
        "dynamic_score": 82,
        "network_score": 78,
    },

    "keylogger_hook.dll": {
        "process_tree": [
            {"pid": 2200, "name": "winlogon.exe",       "parent_pid": None, "label": "NORMAL"},
            {"pid": 3344, "name": "keylogger_hook.dll", "parent_pid": 2200, "label": "SUSPICIOUS"},
            {"pid": 3500, "name": "conhost.exe",        "parent_pid": 3344, "label": "INJECTED"},
        ],
        "resource_usage": {"cpu_pct": 22, "memory_mb": 64, "network_label": "Exfil channel", "disk_io_label": "Low"},
        "behavior_log": [
            ("PROC",  "PID 3344: keylogger_hook.dll — Loaded by winlogon.exe via LoadLibrary"),
            ("PROC",  "PID 3344: SetWindowsHookEx(WH_KEYBOARD_LL) — global keyboard hook installed"),
            ("FILE",  "Created: C:\\Users\\victim\\AppData\\Local\\log_encrypted.dat"),
            ("NET",   "TCP → 45.142.212.100:8080 — Keylog data exfiltration (encrypted)"),
            ("ALERT", "⚠ ALERT: Keylogger hook on logon session — credential theft risk"),
        ],
        "fs_changes": [
            {"operation": "CREATE", "path": "C:\\Users\\victim\\AppData\\Local\\log_encrypted.dat", "detail": "Encrypted keystroke log file"},
        ],
        "reg_changes": [
            {"operation": "SET", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinHook", "detail": "= \"C:\\Windows\\SysWOW64\\keylogger_hook.dll\""},
        ],
        "dynamic_score": 55,
        "network_score": 50,
    },

    "persistence_script.ps1": {
        "process_tree": [
            {"pid": 4000, "name": "powershell.exe",         "parent_pid": None, "label": "SUSPICIOUS"},
            {"pid": 4100, "name": "cmd.exe",                "parent_pid": 4000, "label": "INJECTED"},
            {"pid": 4200, "name": "schtasks.exe",           "parent_pid": 4100, "label": "SUSPICIOUS"},
        ],
        "resource_usage": {"cpu_pct": 12, "memory_mb": 48, "network_label": "None detected", "disk_io_label": "Low"},
        "behavior_log": [
            ("PROC",  "PID 4000: powershell.exe — Execution policy bypass attempted"),
            ("REG",   "HKCU\\...\\Run → Added scheduled task via schtasks.exe"),
            ("FILE",  "Created: C:\\ProgramData\\winupdate.ps1 — Persistent script dropped"),
            ("ALERT", "⚠ ALERT: Persistence via scheduled task and RunKey simultaneously"),
        ],
        "fs_changes": [
            {"operation": "CREATE", "path": "C:\\ProgramData\\winupdate.ps1", "detail": "Persistent PowerShell dropper"},
        ],
        "reg_changes": [
            {"operation": "SET", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WinUpdate", "detail": "= \"powershell -ep bypass -f C:\\ProgramData\\winupdate.ps1\""},
        ],
        "dynamic_score": 72,
        "network_score": 20,
    },

    "ransomware_stub.bin": {
        "process_tree": [
            {"pid": 7000, "name": "ransomware_stub.bin", "parent_pid": None, "label": "MALICIOUS"},
            {"pid": 7100, "name": "vssadmin.exe",        "parent_pid": 7000, "label": "SUSPICIOUS"},
            {"pid": 7200, "name": "wbadmin.exe",         "parent_pid": 7000, "label": "SUSPICIOUS"},
        ],
        "resource_usage": {"cpu_pct": 95, "memory_mb": 1024, "network_label": "Ransom note upload", "disk_io_label": "Very High"},
        "behavior_log": [
            ("PROC",  "PID 7000: ransomware_stub.bin — Process started with elevated privileges"),
            ("FILE",  "Mass RENAME: C:\\Users\\ .doc → .locked (file encryption scan)"),
            ("PROC",  "PID 7100: vssadmin delete shadows /all — shadow copy deletion"),
            ("PROC",  "PID 7200: wbadmin delete catalog — backup catalog wipe"),
            ("FILE",  "Created: C:\\Users\\Desktop\\README_RANSOM.txt — ransom note dropped"),
            ("ALERT", "⚠ ALERT: Mass file encryption behaviour — Ransomware confirmed"),
            ("NET",   "HTTP POST → tor2web proxy — Ransom payment instructions uploaded"),
        ],
        "fs_changes": [
            {"operation": "MODIFY", "path": "C:\\Users\\victim\\Documents\\ (recursive)", "detail": "Mass .locked encryption of 2,412 files"},
            {"operation": "CREATE", "path": "C:\\Users\\Desktop\\README_RANSOM.txt",      "detail": "Ransom note with Bitcoin address"},
            {"operation": "DELETE", "path": "C:\\System Volume Information\\",             "detail": "Shadow copies deleted"},
        ],
        "reg_changes": [
            {"operation": "MODIFY", "key": "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal", "detail": "Forced safe mode reboot for encryption bypass"},
        ],
        "dynamic_score": 97,
        "network_score": 65,
    },

    "resume_clean.pdf": {
        "process_tree": [
            {"pid": 9000, "name": "AcroRd32.exe", "parent_pid": None, "label": "NORMAL"},
        ],
        "resource_usage": {"cpu_pct": 5, "memory_mb": 32, "network_label": "None detected", "disk_io_label": "Minimal"},
        "behavior_log": [
            ("PROC", "PID 9000: AcroRd32.exe — PDF opened normally, no suspicious activity"),
        ],
        "fs_changes": [],
        "reg_changes": [],
        "dynamic_score": 2,
        "network_score": 0,
    },

    "spyware_macro.doc": {
        "process_tree": [
            {"pid": 5000, "name": "WINWORD.EXE",         "parent_pid": None, "label": "NORMAL"},
            {"pid": 5100, "name": "cmd.exe",             "parent_pid": 5000, "label": "SUSPICIOUS"},
            {"pid": 5200, "name": "mshta.exe",           "parent_pid": 5100, "label": "MALICIOUS"},
        ],
        "resource_usage": {"cpu_pct": 35, "memory_mb": 210, "network_label": "Data exfil", "disk_io_label": "Medium"},
        "behavior_log": [
            ("PROC",  "PID 5000: WINWORD.EXE — Document opened, macro execution triggered"),
            ("ALERT", "⚠ ALERT: VBA macro enabled and spawning shell process"),
            ("PROC",  "PID 5100: cmd.exe — Launched by Word macro"),
            ("PROC",  "PID 5200: mshta.exe — HTA payload execution (fileless technique)"),
            ("NET",   "HTTP GET → evil.host.xyz/payload.hta — Remote payload fetch"),
            ("REG",   "HKCU\\Software\\ClipSpy\\settings — Clipboard spy config written"),
        ],
        "fs_changes": [
            {"operation": "CREATE", "path": "C:\\Users\\victim\\AppData\\Local\\Temp\\~WRD0001.tmp", "detail": "Macro-extracted payload"},
        ],
        "reg_changes": [
            {"operation": "CREATE", "key": "HKCU\\Software\\ClipSpy\\settings", "detail": "Clipboard monitoring configuration"},
        ],
        "dynamic_score": 60,
        "network_score": 45,
    },
}

_DEFAULT_PROFILE = {
    "process_tree": [
        {"pid": 1111, "name": "unknown_sample", "parent_pid": None, "label": "SUSPICIOUS"},
    ],
    "resource_usage": {"cpu_pct": 30, "memory_mb": 128, "network_label": "Unknown", "disk_io_label": "Low"},
    "behavior_log": [
        ("PROC", "Process created — behaviour profile unavailable for this sample"),
        ("ALERT", "⚠ ALERT: Unknown sample — manual review recommended"),
    ],
    "fs_changes": [],
    "reg_changes": [],
    "dynamic_score": 35,
    "network_score": 20,
}


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

async def run_dynamic_analysis(
    original_name: str,
    file_id: str,
) -> dict[str, Any]:
    """
    Simulate sandboxed execution and return the dynamic analysis result dict.
    """
    logger.info("[%s] Starting dynamic analysis for '%s'", file_id, original_name)

    profile = _PROFILES.get(original_name.lower(), _DEFAULT_PROFILE)

    # Simulate time steps (process creation, fs monitoring, network capture)
    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY)
    process_tree = profile["process_tree"]

    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    resource_usage = profile["resource_usage"]

    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY)
    behavior_events = _build_event_log(profile["behavior_log"])

    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.5)
    fs_changes  = profile["fs_changes"]
    reg_changes = profile["reg_changes"]

    logger.info(
        "[%s] Dynamic analysis complete: events=%d, fs_changes=%d",
        file_id, len(behavior_events), len(fs_changes),
    )

    return {
        "process_tree":     process_tree,
        "resource_usage":   resource_usage,
        "behavior_events":  behavior_events,
        "filesystem_changes": fs_changes,
        "registry_changes": reg_changes,
        "dynamic_score":    profile["dynamic_score"],
        "network_score":    profile["network_score"],
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _build_event_log(raw_events: list[tuple]) -> list[dict]:
    """Attach formatted timestamps to raw (type, message) tuples."""
    events = []
    for idx, (event_type, message) in enumerate(raw_events):
        minutes = idx // 60
        seconds = (idx * 3) % 60
        ts = f"{minutes:02d}:{seconds:02d}.00"
        events.append({
            "timestamp":  ts,
            "event_type": event_type,
            "message":    message,
        })
    return events
