from __future__ import annotations

import argparse
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, Protocol, TypeAlias, cast

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from evidence_models import (
    CandidateFixRecord,
    DiagnosisRecord,
    EvidenceGroup,
    EvidenceRecord,
    EvidenceRelationship,
    RootCauseCandidate,
    analyze_candidate_fix,
    append_candidate_fix_record,
    append_diagnosis_record,
    append_fix_analysis_record,
    make_candidate_fix_record,
    make_diagnosis_record,
)

import change_applier
from change_transaction import (
    TransactionLogError,
    create_transaction,
    get_transaction,
    transition_transaction,
)
from permission_manager import save_permission
from scope_analyzer import compare_scopes
from change_risk_analyzer import analyze_change_risk


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"
CONTEXT_FILE = LOG_FOLDER / "project_context.jsonl"
DIAGNOSES_FILE = LOG_FOLDER / "diagnoses.jsonl"
CANDIDATE_FIXES_FILE = LOG_FOLDER / "candidate_fixes.jsonl"
FIX_ANALYSES_FILE = LOG_FOLDER / "fix_analyses.jsonl"
CHANGE_TRANSACTIONS_FILE = LOG_FOLDER / "change_transactions.jsonl"

MODEL_NAME = "gemini-3.5-flash-lite"


JsonValue: TypeAlias = (
    None
    | bool
    | int
    | float
    | str
    | list["JsonValue"]
    | dict[str, "JsonValue"]
)

JsonObject: TypeAlias = dict[str, JsonValue]


class ModelsAPI(Protocol):
    def generate_content(
        self,
        *,
        model: str,
        contents: str,
        config: types.GenerateContentConfig | None = None,
    ) -> types.GenerateContentResponse:
        ...


class ExactChange(BaseModel):
    file: str | None = Field(...)
    line: int | None = Field(...)
    old_text: str | None = Field(...)
    new_text: str | None = Field(...)


class Diagnosis(BaseModel):
    status: Literal[
        "NO_TESTS",
        "FAILED",
        "PASSED",
        "UNKNOWN",
    ] = Field(...)

    diagnosis: str = Field(...)
    likely_cause: str = Field(...)

    file: str | None = Field(...)
    line: int | None = Field(...)

    confidence: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
    ] = Field(...)

    evidence: list[str] = Field(...)
    next_step: str = Field(...)

    proposed_change: str = Field(...)
    affected_files: list[str] = Field(...)

    change_size: Literal[
        "NONE",
        "SMALL",
        "MEDIUM",
        "LARGE",
    ] = Field(...)

    exact_change: ExactChange = Field(...)


def to_json_object(
    value: object,
) -> JsonObject | None:
    if not isinstance(
        value,
        dict,
    ):
        return None

    object_value = cast(
        dict[object, object],
        value,
    )

    for key in object_value:
        if not isinstance(
            key,
            str,
        ):
            return None

    return cast(
        JsonObject,
        value,
    )


def load_jsonl(
    path: Path,
) -> list[JsonObject]:
    if not path.exists():
        return []

    records: list[
        JsonObject
    ] = []

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                value: object = (
                    json.loads(line)
                )
            except json.JSONDecodeError:
                continue

            record = to_json_object(
                value
            )

            if record is not None:
                records.append(record)

    return records


def normalize_path(
    path: str,
) -> str:
    return path.replace(
        "\\",
        "/",
    ).lstrip("./")


def _proof_rank(value: str | None) -> int:
    order = {
        "NONE": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "OBSERVED": 4,
    }
    return order.get(value or "LOW", 1)


def _severity_rank(value: str | None) -> int:
    order = {
        "INFO": 0,
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }
    return order.get(value or "LOW", 1)


def _as_evidence_records(items: object) -> list[EvidenceRecord]:
    if not isinstance(items, list):
        return []
    records: list[EvidenceRecord] = []
    for item in items:
        if isinstance(item, dict):
            records.append(cast(EvidenceRecord, item))
    return records


def _group_issue_id(evidence_records: list[EvidenceRecord]) -> str:
    evidence_ids = [
        record["evidence_id"]
        for record in evidence_records
        if isinstance(record.get("evidence_id"), str)
    ]
    if not evidence_ids:
        return "issue-unknown"
    joined = "|".join(sorted(evidence_ids))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]


def _evidence_summary(record: EvidenceRecord) -> str:
    message = record.get("message")
    if isinstance(message, str) and message:
        return message
    return f"Evidence from {record.get('tool_name', 'unknown')}"


def _relationship_map(
    relationships: list[EvidenceRelationship] | None,
) -> dict[str, list[EvidenceRelationship]]:
    mapping: dict[str, list[EvidenceRelationship]] = {}
    if relationships is None:
        return mapping
    for relationship in relationships:
        source_id = relationship.get("source_evidence_id")
        target_id = relationship.get("target_evidence_id")
        if isinstance(source_id, str):
            mapping.setdefault(source_id, []).append(relationship)
        if isinstance(target_id, str):
            mapping.setdefault(target_id, []).append(relationship)
    return mapping


def _build_root_candidates(
    records: list[EvidenceRecord],
    *,
    primary_ids: list[str],
    supporting_ids: list[str],
) -> list[RootCauseCandidate]:
    candidates: list[RootCauseCandidate] = []
    if primary_ids:
        primary_message = _evidence_summary(
            next(record for record in records if record.get("evidence_id") == primary_ids[0])
        )
        candidates.append(
            {
                "role": "ROOT_CAUSE",
                "summary": primary_message,
                "evidence_ids": primary_ids,
                "confidence": "HIGH" if any(record.get("evidence_type") == "RUNTIME_ERROR" for record in records) else "MEDIUM",
            }
        )
    if supporting_ids:
        candidates.append(
            {
                "role": "TRIGGER",
                "summary": "The same code path or location appears in related evidence and strengthens the diagnosis.",
                "evidence_ids": supporting_ids,
                "confidence": "MEDIUM",
            }
        )
    if primary_ids and len(records) > 1:
        candidates.append(
            {
                "role": "CONTRIBUTING_FACTOR",
                "summary": "Related evidence in the same cluster indicates a shared execution path, timing window, or affected location.",
                "evidence_ids": [
                    evidence_id
                    for evidence_id in [record.get("evidence_id") for record in records if isinstance(record.get("evidence_id"), str)]
                    if evidence_id not in primary_ids
                ],
                "confidence": "MEDIUM",
            }
        )
    return candidates


def _select_primary_record(records: list[EvidenceRecord]) -> EvidenceRecord | None:
    if not records:
        return None

    priority_order = {
        "RUNTIME_ERROR": 40,
        "COMPILER_ERROR": 39,
        "TYPE_ERROR": 38,
        "TEST_FAILURE": 35,
        "DEPENDENCY_PROBLEM": 30,
        "CONFIGURATION_PROBLEM": 28,
        "STATIC_WARNING": 20,
    }

    ranked_records = sorted(
        records,
        key=lambda record: (
            priority_order.get(record.get("evidence_type"), 0),
            _proof_rank(record.get("proof_strength")),
            _severity_rank(record.get("severity")),
            record.get("timestamp", ""),
        ),
        reverse=True,
    )
    for record in ranked_records:
        if record.get("status") == "AVAILABLE":
            return record
    return ranked_records[0]


def build_diagnosis_context(
    evidence_records: list[EvidenceRecord],
    *,
    relationships: list[EvidenceRelationship] | None = None,
    groups: list[EvidenceGroup] | None = None,
) -> dict[str, object]:
    primary = _select_primary_record(evidence_records)
    issue_id = _group_issue_id(evidence_records)
    relation_index = _relationship_map(relationships)
    contradictory_ids: list[str] = []
    for record in evidence_records:
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str):
            continue
        related = relation_index.get(evidence_id, [])
        if any(
            relation.get("relationship_type") == "CONTRADICTS"
            for relation in related
            if isinstance(relation, dict)
        ):
            contradictory_ids.append(evidence_id)
    return {
        "issue_id": issue_id,
        "evidence_ids": [
            record["evidence_id"]
            for record in evidence_records
            if isinstance(record.get("evidence_id"), str)
        ],
        "primary_evidence_id": primary["evidence_id"] if primary is not None and isinstance(primary.get("evidence_id"), str) else None,
        "group_ids": [group.get("group_id") for group in (groups or []) if isinstance(group.get("group_id"), str)],
        "contradictory_evidence_ids": contradictory_ids,
        "related_evidence_ids": sorted(
            {
                evidence_id
                for record in evidence_records
                for evidence_id in record.get("related_evidence_ids", [])
                if isinstance(evidence_id, str)
            }
        ),
    }


def _normalize_fix_confidence(value: str | None) -> str:
    if value in {"LOW", "MEDIUM", "HIGH"}:
        return value
    return "MEDIUM"


def generate_candidate_fixes_from_diagnosis(
    diagnosis: DiagnosisRecord,
    *,
    evidence_records: list[EvidenceRecord] | None = None,
    path: str | Path | None = None,
) -> list[CandidateFixRecord]:
    evidence_ids = [
        evidence_id
        for evidence_id in diagnosis.get("primary_evidence", []) + diagnosis.get("supporting_evidence", [])
        if isinstance(evidence_id, str)
    ]
    contradictory_evidence = [
        evidence_id
        for evidence_id in diagnosis.get("contradictory_evidence", [])
        if isinstance(evidence_id, str)
    ]
    affected_locations = [
        location
        for location in diagnosis.get("affected_locations", [])
        if isinstance(location, str)
    ]
    affected_files = [
        path_name
        for path_name in diagnosis.get("affected_files", [])
        if isinstance(path_name, str)
    ]

    candidate_payloads: list[dict[str, object]] = []
    discovered_root_causes = diagnosis.get("root_cause_candidates", [])
    if discovered_root_causes:
        candidate_payloads = [
            {
                "summary": candidate.get("summary", diagnosis.get("selected_root_cause", diagnosis.get("symptom", "Diagnosed failure"))),
                "evidence_ids": candidate.get("evidence_ids", evidence_ids),
                "confidence": candidate.get("confidence", diagnosis.get("fix_confidence", "MEDIUM")),
                "role": candidate.get("role", "ROOT_CAUSE"),
            }
            for candidate in discovered_root_causes
            if isinstance(candidate, dict)
        ]
    if not candidate_payloads:
        root_cause_summary = diagnosis.get("selected_root_cause")
        candidate_payloads = [{
            "summary": root_cause_summary or diagnosis.get("symptom", "The diagnosis is inconclusive and no safe fix should be proposed yet."),
            "evidence_ids": evidence_ids,
            "confidence": diagnosis.get("fix_confidence", "LOW"),
            "role": "ROOT_CAUSE",
        }]

    candidate_fixes: list[CandidateFixRecord] = []
    for candidate in candidate_payloads[:3]:
        summary = str(candidate.get("summary", diagnosis.get("symptom", "Diagnosed issue")))
        diagnosis_confidence = _normalize_fix_confidence(str(diagnosis.get("fix_confidence", "MEDIUM")))
        confidence = diagnosis_confidence
        status: str = "PROPOSED"
        if diagnosis.get("status") in {"INCONCLUSIVE", "SPECULATIVE", "SUSPECTED"} or confidence == "LOW":
            status = "NEEDS_MORE_EVIDENCE"
        elif diagnosis.get("severity") in {"HIGH", "CRITICAL"}:
            status = "REVIEWED"

        fix = make_candidate_fix_record(
            diagnosis_id=diagnosis["diagnosis_id"],
            description=f"Candidate fix for: {summary}",
            proposed_change=(
                "No code changes are proposed until the diagnosis has enough evidence to justify a repair."
                if diagnosis.get("status") in {"INCONCLUSIVE", "SPECULATIVE", "SUSPECTED"}
                else "Apply a narrow validation or guard around the identified root cause before the affected operation."
            ),
            affected_files=affected_files,
            expected_effect=(
                "The diagnosis remains untrusted until stronger evidence confirms the root cause."
                if diagnosis.get("status") in {"INCONCLUSIVE", "SPECULATIVE", "SUSPECTED"}
                else "Mitigates the diagnosed failure while preserving unaffected behavior."
            ),
            assumptions=[
                "The selected root cause remains the best explanation supported by current evidence.",
                "The fix should remain narrow and avoid unrelated code paths.",
            ],
            supporting_evidence=evidence_ids,
            risk=diagnosis.get("severity", "MEDIUM"),
            scope="narrow-scoped" if len(affected_files) <= 1 else "limited multi-file scope",
            validation_plan=list(diagnosis.get("recommended_validation", [])) or ["Repeat the reproducer or failing test.", "Confirm the diagnosis remains consistent with supporting evidence."],
            confidence=confidence,
            issue_id=diagnosis.get("issue_id"),
            status=status,
            primary_evidence=list(diagnosis.get("primary_evidence", [])),
            contradictory_evidence=contradictory_evidence,
            affected_locations=affected_locations,
            root_cause_summary=summary,
            root_cause_candidates=[
                {
                    "role": str(candidate.get("role", "ROOT_CAUSE")),
                    "summary": summary,
                    "evidence_ids": [
                        evidence_id
                        for evidence_id in candidate.get("evidence_ids", [])
                        if isinstance(evidence_id, str)
                    ],
                    "confidence": diagnosis_confidence,
                }
            ],
            constraints=[
                "Do not apply or modify project source files from this record.",
                "Do not bypass permission, validation, scope, or transaction protections.",
                "This fix remains a hypothesis until validation and approval are completed.",
            ],
        )
        candidate_fixes.append(fix)

    if path is not None:
        target = Path(path)
        for fix in candidate_fixes:
            append_candidate_fix_record(target, fix)
            analysis = analyze_candidate_fix(fix, diagnosis=diagnosis)
            append_fix_analysis_record(Path(str(target).replace("candidate_fixes", "fix_analyses")), analysis)

    return candidate_fixes


def diagnose_evidence_group(
    evidence_records: list[EvidenceRecord],
    *,
    group: EvidenceGroup | None = None,
    relationships: list[EvidenceRelationship] | None = None,
    issue_id: str | None = None,
    transaction_id: str | None = None,
) -> DiagnosisRecord:
    if not evidence_records:
        raise ValueError("diagnose_evidence_group requires at least one evidence record.")

    primary = _select_primary_record(evidence_records)
    if primary is None:
        raise ValueError("diagnose_evidence_group could not select primary evidence.")

    evidence_ids = [
        record["evidence_id"]
        for record in evidence_records
        if isinstance(record.get("evidence_id"), str)
    ]
    supporting_ids = [
        evidence_id
        for evidence_id in evidence_ids
        if evidence_id != primary["evidence_id"]
    ]
    relation_map = _relationship_map(relationships)
    contradictory_ids: list[str] = []
    for record in evidence_records:
        evidence_id = record.get("evidence_id")
        if not isinstance(evidence_id, str):
            continue
        related = relation_map.get(evidence_id, [])
        if any(
            relation.get("relationship_type") == "CONTRADICTS"
            for relation in related
            if isinstance(relation, dict)
        ):
            contradictory_ids.append(evidence_id)

    effect_type = primary.get("evidence_type")
    if effect_type == "RUNTIME_ERROR":
        bug_type = "runtime-error"
        status = "CONFIRMED" if primary.get("status") == "AVAILABLE" else "INCONCLUSIVE"
        evidence_strength = "OBSERVED" if primary.get("proof_strength") == "MEDIUM" or primary.get("proof_strength") == "HIGH" else "HIGH"
        diagnostic_confidence = "HIGH" if len(supporting_ids) > 0 else "MEDIUM"
        reproduction_status = "REPRODUCED"
        symptom = primary.get("message", "Observed runtime failure")
        trigger = primary.get("code_location") or "Observed failure at the affected location"
    elif effect_type == "TEST_FAILURE":
        bug_type = "test-regression"
        status = "LIKELY" if primary.get("status") == "AVAILABLE" else "INCONCLUSIVE"
        evidence_strength = "HIGH"
        diagnostic_confidence = "MEDIUM" if len(supporting_ids) > 0 else "LOW"
        reproduction_status = "REPRODUCED"
        symptom = primary.get("message", "Test execution failed")
        trigger = primary.get("code_location") or "The failing test points to the affected code path"
    elif effect_type == "STATIC_WARNING":
        bug_type = "static-analysis"
        status = "SUSPECTED" if primary.get("status") == "AVAILABLE" else "INCONCLUSIVE"
        evidence_strength = "LOW" if primary.get("proof_strength") == "LOW" else "MEDIUM"
        diagnostic_confidence = "LOW" if len(supporting_ids) == 0 else "MEDIUM"
        reproduction_status = "INCONCLUSIVE"
        symptom = primary.get("message", "Static warning suggests a possible issue")
        trigger = primary.get("code_location") or "Static diagnostic identified the affected code path"
    else:
        bug_type = str(effect_type or "unknown-issue").lower()
        status = "INCONCLUSIVE"
        evidence_strength = primary.get("proof_strength", "LOW")
        diagnostic_confidence = "LOW"
        reproduction_status = "INCONCLUSIVE"
        symptom = primary.get("message", "Issue requires additional evidence")
        trigger = primary.get("code_location") or "Issue remains uncertain without stronger evidence"

    affected_files = sorted(
        {
            file_path
            for record in evidence_records
            for file_path in record.get("affected_files", [])
            if isinstance(file_path, str)
        }
    )
    affected_locations = sorted(
        {
            location
            for record in evidence_records
            if isinstance(record.get("code_location"), str)
            for location in [record["code_location"]]
        }
    )

    root_cause_candidates: list[RootCauseCandidate] = _build_root_candidates(
        evidence_records,
        primary_ids=[primary["evidence_id"] if isinstance(primary.get("evidence_id"), str) else ""],
        supporting_ids=[
            evidence_id
            for evidence_id in evidence_ids
            if evidence_id != primary["evidence_id"]
        ],
    )
    selected_root_cause = None
    if root_cause_candidates:
        selected_root_cause = root_cause_candidates[0]["summary"]

    introduced_by_change = None
    if any(
        relation.get("relationship_type") == "RELATED_TO_CHANGE"
        for relation in (relationships or [])
        if isinstance(relation, dict)
    ):
        introduced_by_change = True

    diagnosis = make_diagnosis_record(
        issue_id=issue_id or _group_issue_id(evidence_records),
        bug_type=bug_type,
        status=status,
        evidence_strength=evidence_strength,
        diagnostic_confidence=diagnostic_confidence,
        fix_confidence="LOW",
        severity=primary.get("severity", "MEDIUM"),
        reproduction_status=reproduction_status,
        affected_files=affected_files,
        affected_locations=affected_locations,
        primary_evidence=[primary["evidence_id"]] if isinstance(primary.get("evidence_id"), str) else [],
        supporting_evidence=supporting_ids,
        contradictory_evidence=contradictory_ids,
        symptom=symptom,
        trigger=trigger,
        contributing_factors=[
            record.get("message", "related evidence")
            for record in evidence_records
            if record.get("evidence_id") not in ({primary.get("evidence_id")} if isinstance(primary.get("evidence_id"), str) else set())
        ][:3],
        root_cause_candidates=root_cause_candidates,
        selected_root_cause=selected_root_cause,
        introduced_by_change=introduced_by_change,
        dependency_context=[
            record["message"]
            for record in evidence_records
            if record.get("evidence_type") == "DEPENDENCY_PROBLEM"
            and isinstance(record.get("message"), str)
        ],
        configuration_context=[
            record["message"]
            for record in evidence_records
            if record.get("evidence_type") == "CONFIGURATION_PROBLEM"
            and isinstance(record.get("message"), str)
        ],
        historical_occurrences=[
            record["evidence_id"]
            for record in evidence_records
            if record.get("evidence_id") not in ({primary.get("evidence_id")} if isinstance(primary.get("evidence_id"), str) else set())
        ],
        candidate_fixes=[],
        recommended_validation=[
            "Repeat the failing test or runtime action to confirm the diagnosed failure path.",
            "Validate that the code path matches the affected file and location before making any fix decisions.",
        ],
    )
    diagnosis["fix_confidence"] = "HIGH" if diagnosis["status"] == "CONFIRMED" and diagnosis["diagnostic_confidence"] == "HIGH" else "MEDIUM" if diagnosis["diagnostic_confidence"] == "MEDIUM" else "LOW"
    diagnosis["candidate_fixes"] = [
        fix["fix_id"]
        for fix in generate_candidate_fixes_from_diagnosis(diagnosis)
    ]
    return diagnosis


def diagnose_evidence_records(
    evidence_records: list[EvidenceRecord],
    *,
    groups: list[EvidenceGroup] | None = None,
    relationships: list[EvidenceRelationship] | None = None,
    path: str | Path | None = None,
) -> list[DiagnosisRecord]:
    if not evidence_records:
        return []

    ordered_groups: list[EvidenceGroup] = list(groups or [])
    if not ordered_groups:
        ordered_groups = [
            {
                "group_id": _group_issue_id(evidence_records),
                "evidence_ids": [
                    record["evidence_id"]
                    for record in evidence_records
                    if isinstance(record.get("evidence_id"), str)
                ],
                "relationship_ids": [],
                "summary": "Evidence cluster from detected issue",
                "first_seen": min(
                    (record.get("timestamp", "" ) for record in evidence_records if isinstance(record.get("timestamp"), str)),
                    default=str(datetime.now(timezone.utc).isoformat(timespec="microseconds")),
                ),
                "last_seen": max(
                    (record.get("timestamp", "" ) for record in evidence_records if isinstance(record.get("timestamp"), str)),
                    default=str(datetime.now(timezone.utc).isoformat(timespec="microseconds")),
                ),
                "contradiction_count": 0,
            }
        ]

    by_id = {
        record["evidence_id"]: record
        for record in evidence_records
        if isinstance(record.get("evidence_id"), str)
    }
    diagnoses: list[DiagnosisRecord] = []
    for group in ordered_groups:
        group_ids = group.get("evidence_ids", [])
        records = [
            by_id[evidence_id]
            for evidence_id in group_ids
            if isinstance(evidence_id, str) and evidence_id in by_id
        ]
        if not records:
            continue
        diagnosis = diagnose_evidence_group(
            records,
            group=group,
            relationships=relationships,
            issue_id=str(group.get("group_id", _group_issue_id(records))),
        )
        diagnoses.append(diagnosis)

    if path is not None:
        target = Path(path)
        for diagnosis in diagnoses:
            candidate_fixes = generate_candidate_fixes_from_diagnosis(
                diagnosis,
                evidence_records=evidence_records,
                path=str(target.parent / "candidate_fixes.jsonl"),
            )
            diagnosis["candidate_fixes"] = [fix["fix_id"] for fix in candidate_fixes]
            append_diagnosis_record(target, diagnosis)

    return diagnoses


def persist_diagnoses(
    evidence_records: list[EvidenceRecord],
    *,
    groups: list[EvidenceGroup] | None = None,
    relationships: list[EvidenceRelationship] | None = None,
    path: str | Path = LOG_FOLDER / "diagnoses.jsonl",
) -> list[DiagnosisRecord]:
    return diagnose_evidence_records(
        evidence_records,
        groups=groups,
        relationships=relationships,
        path=path,
    )


def normalize_ai_diagnosis_payload(
    payload: dict[str, object],
    *,
    issue_id: str,
    evidence_ids: list[str],
) -> DiagnosisRecord | None:
    if not isinstance(payload, dict):
        return None
    bug_type = payload.get("bug_type")
    status = payload.get("status")
    evidence_strength = payload.get("evidence_strength")
    diagnostic_confidence = payload.get("diagnostic_confidence")
    fix_confidence = payload.get("fix_confidence")
    severity = payload.get("severity")
    reproduction_status = payload.get("reproduction_status")
    symptom = payload.get("symptom")
    trigger = payload.get("trigger")
    root_candidates = payload.get("root_cause_candidates")
    if not all(isinstance(value, str) for value in [bug_type, status, evidence_strength, diagnostic_confidence, fix_confidence, severity, reproduction_status, symptom, trigger]):
        return None
    candidates: list[RootCauseCandidate] = []
    if isinstance(root_candidates, list):
        for candidate in root_candidates:
            if not isinstance(candidate, dict):
                continue
            role = candidate.get("role")
            summary = candidate.get("summary")
            candidate_evidence_ids = candidate.get("evidence_ids")
            confidence = candidate.get("confidence")
            if isinstance(role, str) and isinstance(summary, str) and isinstance(confidence, str) and isinstance(candidate_evidence_ids, list):
                candidates.append(
                    {
                        "role": role,
                        "summary": summary,
                        "evidence_ids": [value for value in candidate_evidence_ids if isinstance(value, str)],
                        "confidence": confidence,
                    }
                )
    return make_diagnosis_record(
        issue_id=issue_id,
        bug_type=bug_type,
        status=status,
        evidence_strength=evidence_strength,
        diagnostic_confidence=diagnostic_confidence,
        fix_confidence=fix_confidence,
        severity=severity,
        reproduction_status=reproduction_status,
        affected_files=list(payload.get("affected_files", []) if isinstance(payload.get("affected_files"), list) else []),
        affected_locations=list(payload.get("affected_locations", []) if isinstance(payload.get("affected_locations"), list) else []),
        primary_evidence=[
            evidence_id
            for evidence_id in evidence_ids
            if isinstance(evidence_id, str)
        ][:1],
        supporting_evidence=[
            evidence_id
            for evidence_id in evidence_ids
            if isinstance(evidence_id, str)
        ][1:],
        contradictory_evidence=[
            value
            for value in payload.get("contradictory_evidence", [])
            if isinstance(value, str)
        ],
        symptom=symptom,
        trigger=trigger,
        contributing_factors=[
            value
            for value in payload.get("contributing_factors", [])
            if isinstance(value, str)
        ],
        root_cause_candidates=candidates,
        selected_root_cause=payload.get("selected_root_cause") if isinstance(payload.get("selected_root_cause"), str) else None,
        dependency_context=[
            value
            for value in payload.get("dependency_context", [])
            if isinstance(value, str)
        ],
        configuration_context=[
            value
            for value in payload.get("configuration_context", [])
            if isinstance(value, str)
        ],
        historical_occurrences=[
            value
            for value in payload.get("historical_occurrences", [])
            if isinstance(value, str)
        ],
        candidate_fixes=[
            value
            for value in payload.get("candidate_fixes", [])
            if isinstance(value, str)
        ],
        recommended_validation=[
            value
            for value in payload.get("recommended_validation", [])
            if isinstance(value, str)
        ],
    )


def load_evidence() -> list[JsonObject]:
    return load_jsonl(
        EVIDENCE_FILE
    )


def load_project_context() -> list[JsonObject]:
    return load_jsonl(
        CONTEXT_FILE
    )


def get_object(
    record: JsonObject,
    key: str,
) -> JsonObject | None:
    value = record.get(key)

    if not isinstance(
        value,
        dict,
    ):
        return None

    return to_json_object(
        value
    )


def get_string(
    record: JsonObject,
    key: str,
) -> str:
    value = record.get(key)

    if isinstance(
        value,
        str,
    ):
        return value

    return ""


def get_int(
    record: JsonObject,
    key: str,
) -> int | None:
    value = record.get(key)

    if isinstance(
        value,
        int,
    ):
        return value

    return None


def get_test_status(
    evidence: JsonObject,
) -> str:
    test = get_object(
        evidence,
        "test",
    )

    if test is None:
        return "UNKNOWN"

    status = get_string(
        test,
        "status",
    )

    if status:
        return status

    return "UNKNOWN"


def get_affected_file(
    evidence: JsonObject,
) -> str | None:
    test = get_object(
        evidence,
        "test",
    )

    if test is not None:
        failures = test.get(
            "failures"
        )

        if isinstance(
            failures,
            list,
        ):
            for failure in failures:
                if not isinstance(
                    failure,
                    dict,
                ):
                    continue

                failure_object = (
                    to_json_object(
                        failure
                    )
                )

                if failure_object is None:
                    continue

                file = get_string(
                    failure_object,
                    "file",
                )

                if file:
                    return file

    errors = evidence.get(
        "errors"
    )

    if isinstance(
        errors,
        list,
    ):
        for error in errors:
            if not isinstance(
                error,
                dict,
            ):
                continue

            error_object = (
                to_json_object(
                    error
                )
            )

            if error_object is None:
                continue

            file = get_string(
                error_object,
                "file",
            )

            if file:
                return file

    static_analysis = evidence.get(
        "static_analysis"
    )

    if isinstance(
        static_analysis,
        list,
    ):
        for finding in static_analysis:
            if not isinstance(
                finding,
                dict,
            ):
                continue

            finding_object = (
                to_json_object(
                    finding
                )
            )

            if finding_object is None:
                continue

            file = get_string(
                finding_object,
                "file",
            )

            if file:
                return file

    change_session = get_object(
        evidence,
        "change_session",
    )

    if change_session is not None:
        files = change_session.get(
            "files"
        )

        if isinstance(
            files,
            list,
        ):
            for file in files:
                if isinstance(
                    file,
                    str,
                ):
                    return file

    return None


def get_context_for_file(
    context_records: list[JsonObject],
    file_path: str,
) -> JsonObject | None:
    normalized_target = normalize_path(
        file_path
    )

    for record in context_records:
        path = get_string(
            record,
            "path",
        )

        if not path:
            continue

        if (
            normalize_path(path)
            == normalized_target
        ):
            return record

    return None


def get_relevant_context(
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> list[JsonObject]:
    relevant_context: list[
        JsonObject
    ] = []

    affected_file = get_affected_file(
        evidence
    )

    if affected_file:
        context = (
            get_context_for_file(
                context_records,
                affected_file,
            )
        )

        if context is not None:
            relevant_context.append(
                context
            )

    change_session = get_object(
        evidence,
        "change_session",
    )

    if change_session is not None:
        files = change_session.get(
            "files"
        )

        if isinstance(
            files,
            list,
        ):
            for file in files:
                if not isinstance(
                    file,
                    str,
                ):
                    continue

                context = (
                    get_context_for_file(
                        context_records,
                        file,
                    )
                )

                if context is None:
                    continue

                already_added = any(
                    get_string(
                        existing,
                        "path",
                    )
                    == get_string(
                        context,
                        "path",
                    )
                    for existing
                    in relevant_context
                )

                if not already_added:
                    relevant_context.append(
                        context
                    )

    return relevant_context


def build_prompt(
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> str:
    evidence_json = json.dumps(
        evidence,
        indent=2,
        ensure_ascii=False,
    )

    context_json = json.dumps(
        context_records,
        indent=2,
        ensure_ascii=False,
    )

    return f"""
You are an AI Developer Overseer.

Analyze the supplied project evidence and source code.

Your job is to diagnose software problems and propose a change when
the supplied evidence supports one.

Rules:
- Use only the supplied evidence and source context.
- Do not invent files, errors, test results, or source code.
- Identify the most likely cause.
- Identify the affected file when possible.
- Identify the affected line when possible.
- Give a confidence level.
- Give a practical next step.
- If a change is needed, describe the proposed change clearly.
- Do not write replacement code unless it is placed inside the
  exact_change fields.
- Do not produce a full rewritten file.
- Do not propose unrelated improvements.
- Do not change architecture unless the evidence requires it.
- If there is no supported change, use change_size "NONE".
- affected_files must contain only files supported by the evidence
  or supplied source context.

Important source-context rule:
- The supplied source context is the authoritative current source.
- Do not assume source code that is not included in the context.
- If the source context contains the affected test or function,
  inspect it before proposing a change.
- Do not diagnose a specific implementation as incorrect unless
  the supplied source supports that conclusion.

Exact change rules:
- exact_change describes one specific file edit that can be safely
  applied mechanically.
- file must identify the exact file being changed.
- line must identify the relevant line when known.
- old_text must contain the exact existing text that should be
  replaced.
- new_text must contain the exact replacement text.
- Only provide new_text when the supplied evidence and source
  context establish exactly what the replacement should be.
- Never guess a replacement value.
- If the correct replacement cannot be established from the
  supplied evidence, set new_text to null.
- If an exact mechanical edit cannot be established, set the
  exact_change fields to null where appropriate.
- The change applier will refuse to modify files when new_text
  is missing.
- An approved permission does not give permission to guess.

change_size means:
NONE = no change should be made.
SMALL = a localized change affecting a small part of the project.
MEDIUM = a change affecting multiple related parts.
LARGE = a substantial change affecting project architecture or
multiple major components.

The proposed change will be shown to the developer for permission.
Do not assume permission has been granted.

Return only structured data matching the requested schema.

Project evidence:
{evidence_json}

Relevant source context:
{context_json}
""".strip()


def diagnose_evidence(
    client: ModelsAPI,
    evidence: JsonObject,
    context_records: list[JsonObject],
) -> Diagnosis:
    prompt = build_prompt(
        evidence,
        context_records,
    )

    response = client.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=Diagnosis,
            automatic_function_calling=(
                types.AutomaticFunctionCallingConfig(
                    disable=True,
                )
            ),
        ),
    )

    if not response.text:
        raise RuntimeError(
            "AI returned an empty response."
        )

    return Diagnosis.model_validate_json(
        response.text
    )


def write_diagnosis(
    evidence: JsonObject,
    diagnosis: Diagnosis,
    transaction_id: str | None = None,
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    diagnosis_data = (
        diagnosis.model_dump()
    )

    record: JsonObject = {
        "run_id": get_string(
            evidence,
            "run_id",
        ),
        "timestamp": datetime.now(
            timezone.utc
        ).isoformat(
            timespec="milliseconds"
        ),
        "test_timestamp": get_string(
            evidence,
            "timestamp",
        ),
        "test_status": get_test_status(
            evidence,
        ),
        "diagnosis": cast(
            JsonValue,
            diagnosis_data,
        ),
    }
    if transaction_id is not None:
        transaction = get_transaction(
            transaction_id,
            CHANGE_TRANSACTIONS_FILE,
        )
        diagnosis_run_id = get_string(evidence, "run_id")
        if (
            transaction is None
            or transaction["state"] != "PROPOSED"
            or transaction["diagnosis_run_id"] != diagnosis_run_id
            or transaction["pre_change_run_id"] != diagnosis_run_id
        ):
            raise TransactionLogError(
                "Transaction ID does not match the diagnosed test run."
            )
        record["transaction_id"] = transaction_id

    with DIAGNOSES_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                record,
                ensure_ascii=False,
            )
            + "\n"
        )


def candidate_fix_to_permission_diagnosis(
    diagnosis: DiagnosisRecord,
    candidate_fix: CandidateFixRecord,
    *,
    run_id: str,
    test_status: str = "FAILED",
    test_timestamp: str | None = None,
    transaction_id: str | None = None,
    timestamp: str | None = None,
) -> JsonObject:
    affected_files = [
        file_path
        for file_path in candidate_fix.get("affected_files", [])
        if isinstance(file_path, str)
    ]
    if not affected_files:
        affected_files = [
            file_path
            for file_path in diagnosis.get("affected_files", [])
            if isinstance(file_path, str)
        ]

    file_target = affected_files[0] if affected_files else None
    line_number: int | None = None
    affected_locations = [
        location
        for location in diagnosis.get("affected_locations", [])
        if isinstance(location, str)
    ]
    for location in affected_locations:
        if ":" not in location:
            continue
        suffix = location.rsplit(":", 1)[1]
        if suffix.isdigit():
            line_number = int(suffix)
            break

    root_summary = diagnosis.get("selected_root_cause")
    if not isinstance(root_summary, str) or not root_summary:
        root_candidates = diagnosis.get("root_cause_candidates", [])
        for candidate in root_candidates:
            if isinstance(candidate, dict) and isinstance(candidate.get("summary"), str):
                root_summary = candidate["summary"]
                break

    evidence_items = list(candidate_fix.get("supporting_evidence", []))
    evidence_items.extend(list(diagnosis.get("primary_evidence", [])))
    evidence_items.extend(list(diagnosis.get("contradictory_evidence", [])))
    evidence_items = [
        item
        for item in evidence_items
        if isinstance(item, str)
    ]

    if not evidence_items:
        evidence_items = [candidate_fix.get("description", "Candidate fix has no preserved evidence.")]

    exact_change: dict[str, object] = {
        "file": file_target,
        "line": line_number,
        "old_text": None,
        "new_text": None,
    }
    if file_target is None and candidate_fix.get("affected_files"):
        exact_change["file"] = candidate_fix["affected_files"][0]

    change_size = "SMALL"
    if len(affected_files) > 3:
        change_size = "LARGE"
    elif len(affected_files) > 1:
        change_size = "MEDIUM"

    record: JsonObject = {
        "run_id": run_id,
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "test_timestamp": test_timestamp or datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "test_status": test_status,
        "diagnosis": {
            "status": diagnosis.get("status", "INCONCLUSIVE"),
            "diagnosis": diagnosis.get("symptom", "Candidate fix requires human review."),
            "likely_cause": root_summary or "Candidate fix root cause has not been confirmed.",
            "file": file_target,
            "line": line_number,
            "confidence": diagnosis.get("diagnostic_confidence", "MEDIUM"),
            "evidence": evidence_items,
            "next_step": "Review the candidate fix, confirm the diagnosis, and approve the change only after permission is explicitly granted.",
            "proposed_change": candidate_fix.get("proposed_change", "No change proposed."),
            "affected_files": affected_files,
            "change_size": change_size,
            "exact_change": exact_change,
        },
    }
    if transaction_id is not None:
        record["transaction_id"] = transaction_id
    return record


def append_candidate_fix_diagnosis(
    diagnosis: DiagnosisRecord,
    candidate_fix: CandidateFixRecord,
    *,
    run_id: str,
    path: str | Path = DIAGNOSES_FILE,
    test_status: str = "FAILED",
    test_timestamp: str | None = None,
    transaction_id: str | None = None,
    timestamp: str | None = None,
) -> JsonObject:
    record = candidate_fix_to_permission_diagnosis(
        diagnosis,
        candidate_fix,
        run_id=run_id,
        test_status=test_status,
        test_timestamp=test_timestamp,
        transaction_id=transaction_id,
        timestamp=timestamp,
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as file:
        file.write(json.dumps(record, ensure_ascii=False))
        file.write("\n")
    return record


def execute_candidate_fix_pipeline(
    diagnosis: DiagnosisRecord,
    candidate_fix: CandidateFixRecord,
    *,
    run_id: str | None = None,
    transaction_id: str | None = None,
    test_status: str = "FAILED",
    test_timestamp: str | None = None,
    timestamp: str | None = None,
    project_root: Path | None = None,
) -> dict[str, object]:
    originating_run_id = run_id or diagnosis["run_id"]

    permission_diagnosis = candidate_fix_to_permission_diagnosis(
        diagnosis,
        candidate_fix,
        run_id=originating_run_id,
        test_status=test_status,
        test_timestamp=test_timestamp,
        timestamp=timestamp,
        transaction_id=transaction_id,
    )

    diagnosis_data = cast(
        dict[str, object],
        permission_diagnosis["diagnosis"],
    )

    risk_diagnosis: DiagnosisEvidence = {
        "confidence": str(
            diagnosis_data.get("confidence", "MEDIUM")
        ),
        "diagnosis": str(
            diagnosis_data.get(
                "diagnosis",
                "Candidate fix diagnosis",
            )
        ),
        "likely_cause": str(
            diagnosis_data.get(
                "likely_cause",
                "Unknown cause",
            )
        ),
        "proposed_change": str(
            diagnosis_data.get(
                "proposed_change",
                "No change proposed.",
            )
        ),
        "change_size": str(
            diagnosis_data.get(
                "change_size",
                "SMALL",
            )
        ),
        "affected_files": list(
            diagnosis_data.get(
                "affected_files",
                [],
            )
        ),
        "file": cast(
            str | None,
            diagnosis_data.get("file"),
        ),
        "exact_change": cast(
            dict[str, object],
            diagnosis_data.get(
                "exact_change",
                {
                    "file": None,
                    "line": None,
                    "old_text": None,
                    "new_text": None,
                },
            ),
        ),
        "evidence": list(
            diagnosis_data.get(
                "evidence",
                [],
            )
        ),
    }

    risk_assessment = analyze_change_risk(
        risk_diagnosis,
        originating_run_id,
        None,
    )

    try:
        transaction = create_transaction(
            originating_run_id,
            originating_run_id,
            change_applier.CHANGE_TRANSACTIONS_FILE,
        )
    except (
        OSError,
        TransactionLogError,
        ValueError,
    ) as error:
        return {
            "status": "FAILED",
            "diagnosis": permission_diagnosis,
            "permission": None,
            "transaction_id": None,
            "applied": False,
            "scope_status": "FAILED",
            "error": str(error),
        }

    active_transaction_id = transaction["transaction_id"]

    permission_diagnosis["transaction_id"] = active_transaction_id

    try:
        transition_transaction(
            active_transaction_id,
            "PROPOSED",
            "AWAITING_PERMISSION",
            {
                "diagnosis_timestamp": permission_diagnosis[
                    "timestamp"
                ],
                "risk_assessment": risk_assessment,
                "affected_files": list(
                    diagnosis_data.get(
                        "affected_files",
                        [],
                    )
                ),
                "evidence": [
                    "Candidate fix reached the existing permission gate."
                ],
            },
            change_applier.CHANGE_TRANSACTIONS_FILE,
        )
    except (
        InvalidTransactionTransition,
        OSError,
        TransactionLogError,
    ) as error:
        return {
            "status": "FAILED",
            "diagnosis": permission_diagnosis,
            "permission": None,
            "transaction_id": active_transaction_id,
            "applied": False,
            "scope_status": "FAILED",
            "error": str(error),
        }

    print_change_request(
        permission_diagnosis,
        risk_assessment,
        active_transaction_id,
    )

    decision = ask_permission()

    try:
        permission_record = save_permission(
            permission_diagnosis,
            decision,
            active_transaction_id,
            risk_assessment,
        )

        next_state = (
            "APPROVED"
            if decision == "APPROVED"
            else "REJECTED"
        )

        transition_transaction(
            active_transaction_id,
            "AWAITING_PERMISSION",
            next_state,
            {
                "permission_timestamp": permission_record[
                    "permission_timestamp"
                ],
                "permission_decision": decision,
                "affected_files": permission_record[
                    "affected_files"
                ],
                "evidence": [
                    f"Explicit user permission recorded: {decision}."
                ],
            },
            change_applier.CHANGE_TRANSACTIONS_FILE,
        )
    except (
        InvalidTransactionTransition,
        OSError,
        TransactionLogError,
    ) as error:
        return {
            "status": "FAILED",
            "diagnosis": permission_diagnosis,
            "permission": None,
            "transaction_id": active_transaction_id,
            "applied": False,
            "scope_status": "FAILED",
            "error": str(error),
        }

    if decision != "APPROVED":
        return {
            "status": "REJECTED",
            "diagnosis": permission_diagnosis,
            "permission": permission_record,
            "transaction_id": active_transaction_id,
            "applied": False,
            "scope_status": "INCONCLUSIVE",
        }

    applied = change_applier.apply_change(
        permission_diagnosis,
        permission_record,
        active_transaction_id,
    )

    try:
        final_transaction = get_transaction(
            active_transaction_id,
            change_applier.CHANGE_TRANSACTIONS_FILE,
        )
    except TransactionLogError:
        final_transaction = None

    final_status = (
        final_transaction["state"]
        if final_transaction is not None
        else (
            "SUCCEEDED"
            if applied
            else "FAILED"
        )
    )

    return {
        "status": final_status,
        "diagnosis": permission_diagnosis,
        "permission": permission_record,
        "transaction_id": active_transaction_id,
        "applied": applied,
        "scope_status": (
            final_transaction["scope_validation_status"]
            if final_transaction is not None
            else None
        ),
    }


def print_diagnosis(
    diagnosis: Diagnosis,
) -> None:
    print()
    print("=" * 50)
    print("AI DIAGNOSIS")
    print("=" * 50)

    print(
        f"Status: {diagnosis.status}"
    )

    print(
        f"Diagnosis: "
        f"{diagnosis.diagnosis}"
    )

    print(
        f"Likely cause: "
        f"{diagnosis.likely_cause}"
    )

    print(
        f"File: "
        f"{diagnosis.file or 'Unknown'}"
    )

    print(
        f"Line: "
        f"{diagnosis.line or 'Unknown'}"
    )

    print(
        f"Confidence: "
        f"{diagnosis.confidence}"
    )

    print()
    print("Evidence:")

    for evidence_number, evidence_item in enumerate(
        diagnosis.evidence,
        start=1,
    ):
        print(
            f"{evidence_number}. "
            f"{evidence_item}"
        )

    print()

    print(
        f"Next step: "
        f"{diagnosis.next_step}"
    )

    print()

    print(
        "Proposed change:"
    )

    print(
        diagnosis.proposed_change
    )

    print()

    print(
        "Affected files:"
    )

    if diagnosis.affected_files:
        for file_path in (
            diagnosis.affected_files
        ):
            print(
                f"  {file_path}"
            )
    else:
        print(
            "  None"
        )

    print()

    print(
        "Exact change:"
    )

    print(
        f"File: "
        f"{diagnosis.exact_change.file or 'None'}"
    )

    print(
        f"Line: "
        f"{diagnosis.exact_change.line or 'None'}"
    )

    print(
        f"Old text: "
        f"{diagnosis.exact_change.old_text or 'None'}"
    )

    print(
        f"New text: "
        f"{diagnosis.exact_change.new_text or 'None'}"
    )

    print()

    print(
        f"Change size: "
        f"{diagnosis.change_size}"
    )

    print("=" * 50)


def main(transaction_id: str | None = None) -> None:
    evidence_records = load_evidence()

    if not evidence_records:
        print(
            "No evidence found."
        )
        return

    context_records = (
        load_project_context()
    )

    api_key = os.getenv(
        "GEMINI_API_KEY"
    )

    if not api_key:
        print(
            "GEMINI_API_KEY is not set."
        )
        return

    client = genai.Client(
        api_key=api_key,
    )

    for evidence in evidence_records[-1:]:
        try:
            relevant_context = (
                get_relevant_context(
                    evidence,
                    context_records,
                )
            )

            diagnosis = diagnose_evidence(
                client.models,
                evidence,
                relevant_context,
            )

            write_diagnosis(
                evidence,
                diagnosis,
                transaction_id,
            )

            print_diagnosis(
                diagnosis
            )

        except Exception as error:
            print(
                f"Failed to diagnose evidence: "
                f"{error}"
            )
            if transaction_id is not None:
                raise SystemExit(1) from error


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction-id")
    main(parser.parse_args().transaction_id)