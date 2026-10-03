from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, NotRequired, TypedDict

EvidenceType = Literal[
    "COMPILER_ERROR",
    "TYPE_ERROR",
    "STATIC_WARNING",
    "TEST_FAILURE",
    "RUNTIME_ERROR",
    "DEPENDENCY_PROBLEM",
    "CONFIGURATION_PROBLEM",
    "PERFORMANCE_OBSERVATION",
    "MEMORY_OBSERVATION",
    "RESOURCE_OBSERVATION",
    "RACE_EVIDENCE",
    "SECURITY_FINDING",
    "AI_HYPOTHESIS",
]

ProofStrength = Literal["NONE", "LOW", "MEDIUM", "HIGH", "OBSERVED"]
AvailabilityStatus = Literal["AVAILABLE", "UNAVAILABLE", "FAILED", "INCONCLUSIVE"]
DiagnosisStatus = Literal[
    "CONFIRMED",
    "LIKELY",
    "SUSPECTED",
    "INCONCLUSIVE",
    "SPECULATIVE",
]
ConfidenceLevel = Literal["LOW", "MEDIUM", "HIGH"]
SeverityLevel = Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
RootCauseRole = Literal[
    "SYMPTOM",
    "TRIGGER",
    "CONTRIBUTING_FACTOR",
    "ROOT_CAUSE",
]
ReproductionStatus = Literal[
    "NOT_REPRODUCED",
    "REPRODUCED",
    "INCONCLUSIVE",
]


class RootCauseCandidate(TypedDict):
    role: RootCauseRole
    summary: str
    evidence_ids: list[str]
    confidence: ConfidenceLevel


class EvidenceRecord(TypedDict):
    evidence_id: str
    evidence_type: EvidenceType
    tool_name: str
    tool_version: NotRequired[str]
    language: NotRequired[str]
    project_scope: str
    affected_files: list[str]
    code_location: NotRequired[str]
    error_signature: NotRequired[str]
    message: str
    proof_strength: ProofStrength
    severity: NotRequired[SeverityLevel]
    run_id: NotRequired[str]
    transaction_id: NotRequired[str]
    timestamp: str
    correlation_keys: list[str]
    related_evidence_ids: list[str]
    raw_reference: NotRequired[str]
    status: AvailabilityStatus
    availability_note: NotRequired[str]


class DiagnosisRecord(TypedDict):
    diagnosis_id: str
    issue_id: str
    bug_type: str
    status: DiagnosisStatus
    evidence_strength: ProofStrength
    diagnostic_confidence: ConfidenceLevel
    fix_confidence: ConfidenceLevel
    severity: SeverityLevel
    reproduction_status: ReproductionStatus
    affected_files: list[str]
    affected_locations: list[str]
    primary_evidence: list[str]
    supporting_evidence: list[str]
    contradictory_evidence: list[str]
    symptom: str
    trigger: str
    contributing_factors: list[str]
    root_cause_candidates: list[RootCauseCandidate]
    selected_root_cause: NotRequired[str]
    introduced_by_change: NotRequired[bool]
    dependency_context: list[str]
    configuration_context: list[str]
    historical_occurrences: list[str]
    candidate_fixes: list[str]
    recommended_validation: list[str]
    timestamp: str


CandidateFixStatus = Literal[
    "PROPOSED",
    "REVIEWED",
    "ACCEPTED",
    "REJECTED",
    "NEEDS_MORE_EVIDENCE",
]
FixAnalysisStatus = Literal[
    "PROPOSED",
    "REVIEWED",
    "ACCEPTED",
    "REJECTED",
    "NEEDS_MORE_EVIDENCE",
]


class CandidateFixRecord(TypedDict):
    fix_id: str
    diagnosis_id: str
    issue_id: NotRequired[str]
    status: CandidateFixStatus
    description: str
    proposed_change: str
    affected_files: list[str]
    affected_locations: list[str]
    expected_effect: str
    assumptions: list[str]
    primary_evidence: list[str]
    supporting_evidence: list[str]
    contradictory_evidence: list[str]
    root_cause_summary: NotRequired[str]
    root_cause_candidates: NotRequired[list[RootCauseCandidate]]
    constraints: list[str]
    risk: SeverityLevel
    scope: str
    validation_plan: list[str]
    confidence: ConfidenceLevel
    timestamp: str


CandidateFix = CandidateFixRecord


class FixAnalysisRecord(TypedDict):
    analysis_id: str
    fix_id: str
    diagnosis_id: str
    issue_id: NotRequired[str]
    status: FixAnalysisStatus
    summary: str
    risk: SeverityLevel
    confidence: ConfidenceLevel
    assumptions: list[str]
    counter_evidence: list[str]
    validation_plan: list[str]
    concerns: list[str]
    timestamp: str


FixAnalysis = FixAnalysisRecord


RelationshipType = Literal[
    "SUPPORTS",
    "CONTRADICTS",
    "RELATED_TO",
    "CAUSED_BY",
    "OBSERVED_BEFORE",
    "OBSERVED_AFTER",
    "RELATED_TO_CHANGE",
]


class EvidenceRelationship(TypedDict):
    relationship_id: str
    source_evidence_id: str
    target_evidence_id: str
    relationship_type: RelationshipType
    reason: str
    signals: list[str]
    strength: ProofStrength
    timestamp: str
    run_id: NotRequired[str]
    transaction_id: NotRequired[str]
    source_file: NotRequired[str]
    target_file: NotRequired[str]


class EvidenceGroup(TypedDict):
    group_id: str
    evidence_ids: list[str]
    relationship_ids: list[str]
    summary: str
    first_seen: str
    last_seen: str
    run_id: NotRequired[str]
    transaction_id: NotRequired[str]
    temporal_context: NotRequired[str]
    contradiction_count: int


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _append_jsonl(path: Path, record: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True))
        handle.write("\n")


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []

    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            cleaned = line.strip()
            if not cleaned:
                continue
            try:
                value = json.loads(cleaned)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(value)
    return records


def make_evidence_record(
    *,
    evidence_type: EvidenceType,
    tool_name: str,
    project_scope: str,
    message: str,
    affected_files: list[str] | None = None,
    proof_strength: ProofStrength = "LOW",
    status: AvailabilityStatus = "AVAILABLE",
    language: str | None = None,
    tool_version: str | None = None,
    code_location: str | None = None,
    error_signature: str | None = None,
    severity: SeverityLevel | None = None,
    run_id: str | None = None,
    transaction_id: str | None = None,
    correlation_keys: list[str] | None = None,
    related_evidence_ids: list[str] | None = None,
    raw_reference: str | None = None,
    availability_note: str | None = None,
    timestamp: str | None = None,
) -> EvidenceRecord:
    record: EvidenceRecord = {
        "evidence_id": str(uuid.uuid4()),
        "evidence_type": evidence_type,
        "tool_name": tool_name,
        "project_scope": project_scope,
        "affected_files": list(affected_files or []),
        "message": message,
        "proof_strength": proof_strength,
        "status": status,
        "correlation_keys": list(correlation_keys or []),
        "related_evidence_ids": list(related_evidence_ids or []),
        "timestamp": timestamp or _utc_now(),
    }

    if tool_version is not None:
        record["tool_version"] = tool_version
    if language is not None:
        record["language"] = language
    if code_location is not None:
        record["code_location"] = code_location
    if error_signature is not None:
        record["error_signature"] = error_signature
    if severity is not None:
        record["severity"] = severity
    if run_id is not None:
        record["run_id"] = run_id
    if transaction_id is not None:
        record["transaction_id"] = transaction_id
    if raw_reference is not None:
        record["raw_reference"] = raw_reference
    if availability_note is not None:
        record["availability_note"] = availability_note

    return record


def append_evidence_record(path: Path, record: EvidenceRecord) -> EvidenceRecord:
    _append_jsonl(path, dict(record))
    return record


def read_evidence_records(path: Path) -> list[EvidenceRecord]:
    records: list[EvidenceRecord] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records


def make_diagnosis_record(
    *,
    issue_id: str,
    bug_type: str,
    status: DiagnosisStatus,
    evidence_strength: ProofStrength,
    diagnostic_confidence: ConfidenceLevel,
    fix_confidence: ConfidenceLevel,
    severity: SeverityLevel,
    reproduction_status: ReproductionStatus,
    affected_files: list[str],
    affected_locations: list[str],
    primary_evidence: list[str],
    supporting_evidence: list[str],
    contradictory_evidence: list[str],
    symptom: str,
    trigger: str,
    contributing_factors: list[str],
    root_cause_candidates: list[RootCauseCandidate],
    selected_root_cause: str | None = None,
    introduced_by_change: bool | None = None,
    dependency_context: list[str] | None = None,
    configuration_context: list[str] | None = None,
    historical_occurrences: list[str] | None = None,
    candidate_fixes: list[str] | None = None,
    recommended_validation: list[str] | None = None,
    timestamp: str | None = None,
) -> DiagnosisRecord:
    record: DiagnosisRecord = {
        "diagnosis_id": str(uuid.uuid4()),
        "issue_id": issue_id,
        "bug_type": bug_type,
        "status": status,
        "evidence_strength": evidence_strength,
        "diagnostic_confidence": diagnostic_confidence,
        "fix_confidence": fix_confidence,
        "severity": severity,
        "reproduction_status": reproduction_status,
        "affected_files": list(affected_files),
        "affected_locations": list(affected_locations),
        "primary_evidence": list(primary_evidence),
        "supporting_evidence": list(supporting_evidence),
        "contradictory_evidence": list(contradictory_evidence),
        "symptom": symptom,
        "trigger": trigger,
        "contributing_factors": list(contributing_factors),
        "root_cause_candidates": list(root_cause_candidates),
        "dependency_context": list(dependency_context or []),
        "configuration_context": list(configuration_context or []),
        "historical_occurrences": list(historical_occurrences or []),
        "candidate_fixes": list(candidate_fixes or []),
        "recommended_validation": list(recommended_validation or []),
        "timestamp": timestamp or _utc_now(),
    }

    if selected_root_cause is not None:
        record["selected_root_cause"] = selected_root_cause
    if introduced_by_change is not None:
        record["introduced_by_change"] = introduced_by_change
    return record


def append_diagnosis_record(path: Path, record: DiagnosisRecord) -> DiagnosisRecord:
    _append_jsonl(path, dict(record))
    return record


def read_diagnosis_records(path: Path) -> list[DiagnosisRecord]:
    records: list[DiagnosisRecord] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records


def make_candidate_fix_record(
    *,
    diagnosis_id: str,
    description: str,
    proposed_change: str,
    affected_files: list[str],
    expected_effect: str,
    assumptions: list[str],
    supporting_evidence: list[str],
    risk: SeverityLevel,
    scope: str,
    validation_plan: list[str],
    confidence: ConfidenceLevel,
    issue_id: str | None = None,
    status: CandidateFixStatus = "PROPOSED",
    primary_evidence: list[str] | None = None,
    contradictory_evidence: list[str] | None = None,
    affected_locations: list[str] | None = None,
    root_cause_summary: str | None = None,
    root_cause_candidates: list[RootCauseCandidate] | None = None,
    constraints: list[str] | None = None,
    timestamp: str | None = None,
) -> CandidateFixRecord:
    record: CandidateFixRecord = {
        "fix_id": str(uuid.uuid4()),
        "diagnosis_id": diagnosis_id,
        "status": status,
        "description": description,
        "proposed_change": proposed_change,
        "affected_files": list(affected_files),
        "affected_locations": list(affected_locations or []),
        "expected_effect": expected_effect,
        "assumptions": list(assumptions),
        "primary_evidence": list(primary_evidence or []),
        "supporting_evidence": list(supporting_evidence),
        "contradictory_evidence": list(contradictory_evidence or []),
        "constraints": list(constraints or []),
        "risk": risk,
        "scope": scope,
        "validation_plan": list(validation_plan),
        "confidence": confidence,
        "timestamp": timestamp or _utc_now(),
    }
    if issue_id is not None:
        record["issue_id"] = issue_id
    if root_cause_summary is not None:
        record["root_cause_summary"] = root_cause_summary
    if root_cause_candidates is not None:
        record["root_cause_candidates"] = list(root_cause_candidates)
    return record


def append_candidate_fix_record(
    path: Path,
    record: CandidateFixRecord,
) -> CandidateFixRecord:
    _append_jsonl(path, dict(record))
    return record


def read_candidate_fix_records(path: Path) -> list[CandidateFixRecord]:
    records: list[CandidateFixRecord] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records


def make_fix_analysis_record(
    *,
    fix_id: str,
    diagnosis_id: str,
    summary: str,
    risk: SeverityLevel,
    confidence: ConfidenceLevel,
    assumptions: list[str] | None = None,
    counter_evidence: list[str] | None = None,
    validation_plan: list[str] | None = None,
    concerns: list[str] | None = None,
    issue_id: str | None = None,
    status: FixAnalysisStatus = "PROPOSED",
    timestamp: str | None = None,
) -> FixAnalysisRecord:
    record: FixAnalysisRecord = {
        "analysis_id": str(uuid.uuid4()),
        "fix_id": fix_id,
        "diagnosis_id": diagnosis_id,
        "status": status,
        "summary": summary,
        "risk": risk,
        "confidence": confidence,
        "assumptions": list(assumptions or []),
        "counter_evidence": list(counter_evidence or []),
        "validation_plan": list(validation_plan or []),
        "concerns": list(concerns or []),
        "timestamp": timestamp or _utc_now(),
    }
    if issue_id is not None:
        record["issue_id"] = issue_id
    return record


def append_fix_analysis_record(
    path: Path,
    record: FixAnalysisRecord,
) -> FixAnalysisRecord:
    _append_jsonl(path, dict(record))
    return record


def read_fix_analysis_records(path: Path) -> list[FixAnalysisRecord]:
    records: list[FixAnalysisRecord] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records


def analyze_candidate_fix(
    fix: CandidateFixRecord,
    *,
    diagnosis: DiagnosisRecord | None = None,
) -> FixAnalysisRecord:
    issue_id = fix.get("issue_id") or (diagnosis.get("issue_id") if diagnosis is not None else None)
    status: FixAnalysisStatus = "REVIEWED"
    if fix["confidence"] == "LOW":
        status = "NEEDS_MORE_EVIDENCE"
    elif fix["risk"] in {"HIGH", "CRITICAL"}:
        status = "REJECTED"
    elif fix["confidence"] == "HIGH" and fix["risk"] in {"LOW", "MEDIUM"}:
        status = "ACCEPTED"

    summary = (
        "Candidate fix hypothesis reviewed against diagnosis evidence and validation constraints. "
        f"Status: {status}. "
        f"Risk: {fix['risk']}. Confidence: {fix['confidence']}."
    )
    validation_plan = list(fix.get("validation_plan", []))
    if not validation_plan:
        validation_plan = ["Run the relevant failing test or reproducer."]

    concerns: list[str] = []
    if fix["risk"] in {"HIGH", "CRITICAL"}:
        concerns.append("High-risk change with non-trivial blast radius.")
    if fix["confidence"] == "LOW":
        concerns.append("Fix confidence is low; additional reproduction or evidence is needed.")

    return make_fix_analysis_record(
        fix_id=fix["fix_id"],
        diagnosis_id=fix["diagnosis_id"],
        summary=summary,
        risk=fix["risk"],
        confidence=fix["confidence"],
        assumptions=fix.get("assumptions", []),
        counter_evidence=[],
        validation_plan=validation_plan,
        concerns=concerns,
        issue_id=issue_id,
        status=status,
    )


def make_evidence_relationship(
    *,
    source_evidence_id: str,
    target_evidence_id: str,
    relationship_type: RelationshipType,
    reason: str,
    signals: list[str],
    strength: ProofStrength,
    timestamp: str | None = None,
    run_id: str | None = None,
    transaction_id: str | None = None,
    source_file: str | None = None,
    target_file: str | None = None,
) -> EvidenceRelationship:
    relationship_key = (
        f"{source_evidence_id}|{target_evidence_id}|{relationship_type}|{reason}"
    )
    digest = hashlib.sha256(relationship_key.encode("utf-8")).hexdigest()[:16]
    record: EvidenceRelationship = {
        "relationship_id": digest,
        "source_evidence_id": source_evidence_id,
        "target_evidence_id": target_evidence_id,
        "relationship_type": relationship_type,
        "reason": reason,
        "signals": list(signals),
        "strength": strength,
        "timestamp": timestamp or _utc_now(),
    }
    if run_id is not None:
        record["run_id"] = run_id
    if transaction_id is not None:
        record["transaction_id"] = transaction_id
    if source_file is not None:
        record["source_file"] = source_file
    if target_file is not None:
        record["target_file"] = target_file
    return record


def append_evidence_relationship(
    path: Path,
    record: EvidenceRelationship,
) -> EvidenceRelationship:
    _append_jsonl(path, dict(record))
    return record


def read_evidence_relationships(path: Path) -> list[EvidenceRelationship]:
    records: list[EvidenceRelationship] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records


def make_evidence_group(
    *,
    evidence_ids: list[str],
    relationship_ids: list[str],
    summary: str,
    first_seen: str,
    last_seen: str,
    contradiction_count: int = 0,
    run_id: str | None = None,
    transaction_id: str | None = None,
    temporal_context: str | None = None,
) -> EvidenceGroup:
    group_key = "|".join(sorted(evidence_ids)) if evidence_ids else "empty-group"
    group_digest = hashlib.sha256(group_key.encode("utf-8")).hexdigest()[:16]
    record: EvidenceGroup = {
        "group_id": group_digest,
        "evidence_ids": list(evidence_ids),
        "relationship_ids": list(relationship_ids),
        "summary": summary,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "contradiction_count": contradiction_count,
    }
    if run_id is not None:
        record["run_id"] = run_id
    if transaction_id is not None:
        record["transaction_id"] = transaction_id
    if temporal_context is not None:
        record["temporal_context"] = temporal_context
    return record


def append_evidence_group(
    path: Path,
    record: EvidenceGroup,
) -> EvidenceGroup:
    _append_jsonl(path, dict(record))
    return record


def read_evidence_groups(path: Path) -> list[EvidenceGroup]:
    records: list[EvidenceGroup] = []
    for entry in _read_jsonl(path):
        if isinstance(entry, dict):
            records.append(entry)
    return records
