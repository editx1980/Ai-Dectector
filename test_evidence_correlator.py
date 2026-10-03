from __future__ import annotations

import json
from pathlib import Path

from evidence_correlator import correlate_evidence_records, persist_correlated_evidence
from evidence_models import (
    make_evidence_record,
    read_evidence_groups,
    read_evidence_relationships,
)
from evidence_normalizer import (
    normalize_static_analysis_record,
    normalize_test_result,
)


def test_same_run_and_transaction_create_related_evidence() -> None:
    first = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name="pytest",
        project_scope="project-root",
        message="Assertion failed.",
        affected_files=["src/service.lua"],
        proof_strength="HIGH",
        status="AVAILABLE",
        run_id="run-abc",
        transaction_id="txn-123",
        code_location="src/service.lua:42",
        error_signature="assertion-failed",
        correlation_keys=["shared_run"],
        related_evidence_ids=[],
    )
    second = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime blew up at the same location.",
        affected_files=["src/service.lua"],
        proof_strength="MEDIUM",
        status="AVAILABLE",
        run_id="run-abc",
        transaction_id="txn-123",
        code_location="src/service.lua:42",
        error_signature="assertion-failed",
        correlation_keys=["shared_run"],
        related_evidence_ids=[],
    )

    relationships, groups = correlate_evidence_records([first, second])

    assert any(
        relation["relationship_type"] == "RELATED_TO"
        and "shared_run_id" in relation["signals"]
        for relation in relationships
    )
    assert any(
        relation["relationship_type"] == "RELATED_TO_CHANGE"
        for relation in relationships
    )
    assert any(
        relation["relationship_type"] == "RELATED_TO"
        and "matching_error_signature" in relation["signals"]
        for relation in relationships
    )
    assert groups and any(len(group["evidence_ids"]) == 2 for group in groups)


def test_same_file_and_location_create_earlier_later_relationships() -> None:
    earlier = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="luau-analyze",
        project_scope="project-root",
        message="Possible nil access in script.",
        affected_files=["src/ServerScript.luau"],
        proof_strength="LOW",
        status="AVAILABLE",
        code_location="src/ServerScript.luau:7",
        timestamp="2026-10-03T12:00:00+00:00",
    )
    later = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Nil access at same location.",
        affected_files=["src/ServerScript.luau"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="src/ServerScript.luau:7",
        timestamp="2026-10-03T12:05:00+00:00",
    )

    relationships, _ = correlate_evidence_records([earlier, later])
    assert any(
        relation["relationship_type"] == "OBSERVED_BEFORE"
        and relation["source_evidence_id"] == earlier["evidence_id"]
        for relation in relationships
    )
    assert any(
        relation["relationship_type"] == "RELATED_TO"
        and "same_code_location" in relation["signals"]
        for relation in relationships
    )


def test_contradictory_evidence_is_preserved() -> None:
    static = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="ruff",
        project_scope="project-root",
        message="Tool unavailable or weak signal.",
        affected_files=["src/alpha.py"],
        proof_strength="NONE",
        status="UNAVAILABLE",
        availability_note="Tool unavailable in this environment.",
    )
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Command failed while executing alpha.py.",
        affected_files=["src/alpha.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
    )

    relationships, _ = correlate_evidence_records([static, runtime])
    assert any(
        relation["relationship_type"] == "CONTRADICTS"
        for relation in relationships
    )


def test_persistence_prevents_duplicate_relationships() -> None:
    relationship_path = Path("logs/test_relationships.jsonl")
    group_path = Path("logs/test_groups.jsonl")
    if relationship_path.exists():
        relationship_path.unlink()
    if group_path.exists():
        group_path.unlink()

    first = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name="pytest",
        project_scope="project-root",
        message="No tests found.",
        affected_files=["tests/example.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        run_id="run-dup",
    )
    second = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime failure in same area.",
        affected_files=["tests/example.py"],
        proof_strength="MEDIUM",
        status="AVAILABLE",
        run_id="run-dup",
    )

    persist_correlated_evidence([first, second], relationship_path=relationship_path, group_path=group_path)
    persist_correlated_evidence([first, second], relationship_path=relationship_path, group_path=group_path)

    relationships = read_evidence_relationships(relationship_path)
    groups = read_evidence_groups(group_path)
    assert len(relationships) >= 1
    assert len(groups) >= 1
    assert len({relationship["relationship_id"] for relationship in relationships}) == len(relationships)


def test_phase3_integration_uses_normalized_evidence_and_persists_groups() -> None:
    static_path = Path("logs/test_phase3_static.jsonl")
    test_path = Path("logs/test_phase3_test_results.jsonl")
    relationship_path = Path("logs/test_phase3_relationships.jsonl")
    group_path = Path("logs/test_phase3_groups.jsonl")

    for path in (static_path, test_path, relationship_path, group_path):
        if path.exists():
            path.unlink()

    static_records = [
        {
            "tool": "ruff",
            "language": "Python",
            "available": True,
            "exit_code": 1,
            "findings": [
                {
                    "tool": "ruff",
                    "language": "Python",
                    "severity": "ERROR",
                    "message": "unused import",
                    "file": "src/service.py",
                    "line": 7,
                    "column": 1,
                    "raw_output": "src/service.py:7:1: F401 unused import",
                }
            ],
        }
    ]
    test_records = [
        {
            "run_id": "phase3-run",
            "timestamp": "2026-10-03T12:00:00Z",
            "command": ["python", "-m", "pytest"],
            "status": "FAILED",
            "output": "FAILED src/test_service.py::test_service",
            "failures": [{"file": "src/service.py", "line": 12, "test": "test_service"}],
        }
    ]

    normalized = []
    for row in static_records:
        normalized.extend(normalize_static_analysis_record(row, source_name="test_phase3_static.jsonl"))
    for row in test_records:
        normalized.extend(normalize_test_result(row, source_name="test_phase3_test_results.jsonl"))

    relationships, groups = persist_correlated_evidence(
        normalized,
        relationship_path=relationship_path,
        group_path=group_path,
    )

    assert len(normalized) == 2
    assert any(relation["relationship_type"] == "RELATED_TO" for relation in relationships)
    assert any(group["evidence_ids"] for group in groups)

    persisted_relationships = read_evidence_relationships(relationship_path)
    persisted_groups = read_evidence_groups(group_path)
    assert len(persisted_relationships) >= 1
    assert len(persisted_groups) >= 1

    raw_output = json.dumps({"relationships": persisted_relationships, "groups": persisted_groups})
    assert "relationship_id" in raw_output
