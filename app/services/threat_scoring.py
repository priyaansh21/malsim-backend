"""
services/threat_scoring.py — Composite threat scoring & YARA-style rule engine.

Aggregates signals from static + dynamic analysis into a 0–100 threat score.
Also runs the YARA-style rule matching and IP reputation checks.

Scoring formula (mirrors the UI's algorithm panel):
  composite = (static * 0.35) + (dynamic * 0.30) + (yara * 0.20) + (network * 0.15)
  Risk bands: ≥70 → HIGH | 40–69 → MEDIUM | <40 → CLEAN / LOW
"""

import asyncio
from typing import Any

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# YARA-STYLE RULES
# ═══════════════════════════════════════════════════════════════════════════════

YARA_RULES = [
    {
        "rule_name": "ProcessInjection_VirtualAllocEx",
        "strings": '$a = "VirtualAllocEx" $b = "WriteProcessMemory" $c = "CreateRemoteThread"',
        "condition": 'all of them → Detected classic process injection triad',
        "trigger_keywords": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
        "weight": 25,
    },
    {
        "rule_name": "Persistence_RunKey",
        "strings": '$reg = "CurrentVersion\\\\Run" $cmd = "cmd.exe" $ps = "powershell"',
        "condition": '$reg and any of ($cmd, $ps) → Registry persistence with shell execution',
        "trigger_keywords": {"CurrentVersion\\Run", "Run\\SvcUpdate"},
        "weight": 20,
    },
    {
        "rule_name": "AntiAnalysis_Evasion",
        "strings": '$d = "IsDebuggerPresent" $t = "NtSetInformationThread"',
        "condition": 'any of them → Anti-debug / anti-analysis techniques detected',
        "trigger_keywords": {"IsDebuggerPresent", "NtSetInformationThread"},
        "weight": 18,
    },
    {
        "rule_name": "HighEntropy_Packing",
        "strings": 'meta: entropy_threshold = 7.5 | strings: $upx = "UPX!" $upx0 = ".upx0"',
        "condition": 'entropy > 7.5 and any of ($upx, $upx0) → UPX-packed binary, possible obfuscation',
        "trigger_keywords": {"UPX", "upx0", ".upx0"},
        "weight": 15,
    },
    {
        "rule_name": "NetworkC2_Beacon",
        "strings": '$dns = "WSAStartup" $sock = "connect" $dns2 = "gethostbyname"',
        "condition": 'all of them → C2 beacon socket strings',
        "trigger_keywords": {"WSAStartup", "gethostbyname", "C2 beacon"},
        "weight": 22,
    },
    {
        "rule_name": "Ransomware_ShadowDelete",
        "strings": '$a = "vssadmin" $b = "delete shadows" $c = "wbadmin"',
        "condition": 'any of them → Volume shadow copy deletion (ransomware indicator)',
        "trigger_keywords": {"vssadmin", "shadow", "wbadmin"},
        "weight": 30,
    },
]

# IP Reputation Database (simulated threat intel feed)
IP_REPUTATION_DB = [
    {"ip": "185.220.101.47", "reputation": "MALICIOUS",  "detail": "TOR exit node · Metasploit C2"},
    {"ip": "92.223.89.12",   "reputation": "MALICIOUS",  "detail": "Fast-flux · FastFlux botnet"},
    {"ip": "45.142.212.100", "reputation": "MALICIOUS",  "detail": "Cobalt Strike beacon"},
    {"ip": "8.8.8.8",        "reputation": "CLEAN",      "detail": "Google DNS — benign"},
    {"ip": "1.1.1.1",        "reputation": "CLEAN",      "detail": "Cloudflare DNS — benign"},
]

# Profile → known IOC IPs
PROFILE_C2_IPS: dict[str, list[str]] = {
    "trojan_dropper_sim.exe": ["185.220.101.47", "92.223.89.12", "45.142.212.100", "8.8.8.8"],
    "keylogger_hook.dll":     ["45.142.212.100"],
    "ransomware_stub.bin":    ["185.220.101.47"],
    "spyware_macro.doc":      ["92.223.89.12"],
}

# Profile → YARA rule hits
PROFILE_YARA_HITS: dict[str, set[str]] = {
    "trojan_dropper_sim.exe": {
        "ProcessInjection_VirtualAllocEx", "Persistence_RunKey",
        "AntiAnalysis_Evasion", "HighEntropy_Packing",
    },
    "keylogger_hook.dll": {"Persistence_RunKey", "AntiAnalysis_Evasion"},
    "persistence_script.ps1": {"Persistence_RunKey"},
    "ransomware_stub.bin": {
        "HighEntropy_Packing", "Persistence_RunKey", "Ransomware_ShadowDelete",
    },
    "resume_clean.pdf": set(),
    "spyware_macro.doc": {"Persistence_RunKey", "NetworkC2_Beacon"},
}

# Profile → metadata
THREAT_METADATA: dict[str, dict] = {
    "trojan_dropper_sim.exe": {
        "category": "Trojan.Dropper",
        "tags": ["TROJAN", "PROCESS INJECTION", "PERSISTENCE", "ANTI-DEBUG", "C2 BEACON"],
        "recommendation": "ISOLATE",
    },
    "keylogger_hook.dll": {
        "category": "Spyware.Keylogger",
        "tags": ["KEYLOGGER", "PERSISTENCE", "DATA EXFIL"],
        "recommendation": "ISOLATE",
    },
    "persistence_script.ps1": {
        "category": "Malware.Persistence",
        "tags": ["PERSISTENCE", "POWERSHELL", "SCRIPT"],
        "recommendation": "ISOLATE",
    },
    "ransomware_stub.bin": {
        "category": "Ransomware.FileEncryptor",
        "tags": ["RANSOMWARE", "FILE ENCRYPTION", "SHADOW DELETE", "HIGH ENTROPY"],
        "recommendation": "ISOLATE",
    },
    "resume_clean.pdf": {
        "category": "Clean",
        "tags": ["CLEAN", "BENIGN"],
        "recommendation": "ALLOW",
    },
    "spyware_macro.doc": {
        "category": "Spyware.MacroEmbedded",
        "tags": ["SPYWARE", "MACRO", "DATA EXFIL"],
        "recommendation": "MONITOR",
    },
}


# ═══════════════════════════════════════════════════════════════════════════════
# ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

async def run_threat_scoring(
    original_name: str,
    file_id: str,
    static_result: dict[str, Any],
    dynamic_result: dict[str, Any],
) -> dict[str, Any]:
    """
    Aggregate sub-scores into composite threat score and produce final verdict.
    """
    logger.info("[%s] Starting threat scoring for '%s'", file_id, original_name)

    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.3)

    # ── Sub-scores ─────────────────────────────────────────────────────────────
    static_score  = static_result.get("static_score",  0.0)
    dynamic_score = dynamic_result.get("dynamic_score", 0.0)
    network_score = dynamic_result.get("network_score", 0.0)

    # ── YARA Matching ──────────────────────────────────────────────────────────
    yara_hits    = PROFILE_YARA_HITS.get(original_name.lower(), set())
    yara_results = _run_yara_rules(yara_hits)
    yara_score   = round(min(len(yara_hits) * 20, 100), 2)

    await asyncio.sleep(settings.SANDBOX_SIMULATION_DELAY * 0.3)

    # ── Network IOC Lookup ─────────────────────────────────────────────────────
    c2_ips       = PROFILE_C2_IPS.get(original_name.lower(), [])
    network_iocs = _lookup_ips(c2_ips)

    # ── Composite Score ────────────────────────────────────────────────────────
    composite = (
        static_score  * 0.35 +
        dynamic_score * 0.30 +
        yara_score    * 0.20 +
        network_score * 0.15
    )
    composite = round(min(composite, 100), 2)

    # ── Risk classification ────────────────────────────────────────────────────
    risk_level = _classify_risk(composite)

    # ── Metadata ───────────────────────────────────────────────────────────────
    meta = THREAT_METADATA.get(original_name.lower(), {
        "category": "Unknown",
        "tags": ["UNKNOWN"],
        "recommendation": "MONITOR",
    })

    algorithm_explanation = (
        f"composite = (static {static_score:.0f} × 0.35) + "
        f"(dynamic {dynamic_score:.0f} × 0.30) + "
        f"(yara {yara_score:.0f} × 0.20) + "
        f"(network {network_score:.0f} × 0.15) = {composite:.0f}/100"
    )

    logger.info(
        "[%s] Threat scoring complete: composite=%.1f, risk=%s",
        file_id, composite, risk_level,
    )

    return {
        "threat_score":    composite,
        "risk_level":      risk_level,
        "threat_category": meta["category"],
        "recommendation":  meta["recommendation"],
        "tags":            meta["tags"],
        "score_breakdown": {
            "static_score":    static_score,
            "dynamic_score":   dynamic_score,
            "signature_score": static_score,    # proxy (sig matching drives static)
            "yara_score":      yara_score,
            "network_score":   network_score,
            "composite_score": composite,
        },
        "yara_results":  yara_results,
        "network_iocs":  network_iocs,
        "algorithm_explanation": algorithm_explanation,
        "yara_score":   yara_score,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_risk(score: float) -> str:
    if score >= 70:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 10:
        return "LOW"
    return "CLEAN"


def _run_yara_rules(hits: set[str]) -> list[dict]:
    results = []
    for rule in YARA_RULES:
        results.append({
            "rule_name": rule["rule_name"],
            "matched":   rule["rule_name"] in hits,
            "strings":   rule["strings"],
            "condition": rule["condition"],
        })
    return results


def _lookup_ips(c2_ips: list[str]) -> list[dict]:
    if not c2_ips:
        return []
    ip_map = {entry["ip"]: entry for entry in IP_REPUTATION_DB}
    result = []
    for ip in c2_ips:
        if ip in ip_map:
            result.append(ip_map[ip])
        else:
            result.append({"ip": ip, "reputation": "UNKNOWN", "detail": "Not in threat intel DB"})
    return result
