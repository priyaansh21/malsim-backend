"""
models/schemas.py — Pydantic v2 schemas for request/response serialisation.

Separation of concerns:
  - Request schemas  → validate incoming data
  - Response schemas → shape outgoing JSON (matched to frontend expectations)
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional, List

from pydantic import BaseModel, Field, ConfigDict


# ═══════════════════════════════════════════════════════════════════════════════
# SHARED / BASE
# ═══════════════════════════════════════════════════════════════════════════════

class OKResponse(BaseModel):
    ok: bool = True
    message: str


# ═══════════════════════════════════════════════════════════════════════════════
# UPLOAD — POST /upload
# ═══════════════════════════════════════════════════════════════════════════════

class UploadResponse(BaseModel):
    id: str
    filename: str
    file_size: int
    extension: str
    status: str          # "queued"
    created_at: datetime
    message: str = "File accepted for analysis"


# ═══════════════════════════════════════════════════════════════════════════════
# STATIC ANALYSIS — GET /static-analysis/{id}
# ═══════════════════════════════════════════════════════════════════════════════

class HashMetadata(BaseModel):
    filename: str
    md5: str
    sha1: str
    sha256: str
    file_size: str          # human-readable
    file_type: str
    entropy: float
    entropy_label: str
    compile_time: str
    sections: str
    packer: Optional[str] = None


class SuspiciousString(BaseModel):
    severity: str           # CRITICAL | HIGH | MED | LOW
    value: str
    category: str           # API | REG | CMD | STR | NET


class SignatureMatch(BaseModel):
    sig_id: str
    name: str
    matched: bool


class StaticAnalysisResponse(BaseModel):
    id: str
    status: str
    filename: str
    hash_metadata: Optional[HashMetadata] = None
    suspicious_strings: List[SuspiciousString] = []
    signature_matches: List[SignatureMatch] = []
    alert: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# DYNAMIC ANALYSIS — GET /dynamic-analysis/{id}
# ═══════════════════════════════════════════════════════════════════════════════

class ProcessNode(BaseModel):
    pid: int
    name: str
    parent_pid: Optional[int] = None
    label: str              # SUSPICIOUS | INJECTED | MALICIOUS | HOLLOWED | NORMAL


class ResourceUsage(BaseModel):
    cpu_pct: float
    memory_mb: float
    network_label: str
    disk_io_label: str


class BehaviorEvent(BaseModel):
    timestamp: str
    event_type: str         # PROC | FILE | REG | NET | ALERT
    message: str


class FileSystemChange(BaseModel):
    operation: str          # WRITE | CREATE | MODIFY | DELETE
    path: str
    detail: str


class RegistryChange(BaseModel):
    operation: str          # SET | MODIFY | CREATE
    key: str
    detail: str


class DynamicAnalysisResponse(BaseModel):
    id: str
    status: str
    filename: str
    process_tree: List[ProcessNode] = []
    resource_usage: Optional[ResourceUsage] = None
    behavior_events: List[BehaviorEvent] = []
    filesystem_changes: List[FileSystemChange] = []
    registry_changes: List[RegistryChange] = []


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT SCORE — GET /threat-score/{id}
# ═══════════════════════════════════════════════════════════════════════════════

class ScoreBreakdown(BaseModel):
    static_score: float
    dynamic_score: float
    signature_score: float
    yara_score: float
    network_score: float
    composite_score: float


class YaraRuleResult(BaseModel):
    rule_name: str
    matched: bool
    strings: str
    condition: str


class NetworkIOC(BaseModel):
    ip: str
    reputation: str         # MALICIOUS | SUSPICIOUS | CLEAN
    detail: str


class ThreatScoreResponse(BaseModel):
    id: str
    status: str
    filename: str
    threat_score: Optional[float] = None
    risk_level: Optional[str] = None
    threat_category: Optional[str] = None
    recommendation: Optional[str] = None
    tags: List[str] = []
    score_breakdown: Optional[ScoreBreakdown] = None
    yara_results: List[YaraRuleResult] = []
    network_iocs: List[NetworkIOC] = []
    algorithm_explanation: Optional[str] = None


# ═══════════════════════════════════════════════════════════════════════════════
# QUEUE / STATUS — GET /status/{id}  &  GET /queue
# ═══════════════════════════════════════════════════════════════════════════════

class QueueItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    original_name: str
    file_size: int
    extension: Optional[str]
    status: str
    threat_score: Optional[float] = None
    risk_level: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    completed_at: Optional[datetime] = None


class QueueListResponse(BaseModel):
    total: int
    items: List[QueueItem]


# ═══════════════════════════════════════════════════════════════════════════════
# DASHBOARD STATS — GET /dashboard/stats
# ═══════════════════════════════════════════════════════════════════════════════

class CategoryCount(BaseModel):
    label: str
    count: int
    color: str


class DashboardStats(BaseModel):
    total_scanned: int
    high_risk: int
    medium_risk: int
    clean_files: int
    rules_matched: int
    processing: int
    queued: int
    categories: List[CategoryCount] = []


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR
# ═══════════════════════════════════════════════════════════════════════════════

class ErrorResponse(BaseModel):
    ok: bool = False
    error: str
    detail: Optional[Any] = None
