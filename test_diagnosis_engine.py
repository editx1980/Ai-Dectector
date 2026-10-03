from __future__ import annotations

from pathlib import Path

from ai_diagnoser import (
    diagnose_evidence_group,
    diagnose_evidence_records,
    generate_candidate_fixes_from_diagnosis,
    normalize_ai_diagnosis_payload,
)
from evidence_models import (
    analyze_candidate_fix,
    append_candidate_fix_record,
    append_fix_analysis_record,
    make_evidence_record,
    make_evidence_relationship,
    read_candidate_fix_records,
    read_diagnosis_records,
    read_fix_analysis_records,
)


def test_runtime_and_test_evidence_create_diagnosis_with_root_cause_candidates() -> None:
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="AttributeError: 'NoneType' object has no attribute 'value'",
        affected_files=["src/service.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="src/service.py:42",
        severity="HIGH",
        run_id="run-100",
    )
    failing_test = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name="pytest",
        project_scope="project-root",
        message="AssertionError in test_service",
        affected_files=["src/service.py", "tests/test_service.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="tests/test_service.py:12",
        severity="HIGH",
        run_id="run-100",
        error_signature="test_service",
    )

    diagnosis = diagnose_evidence_group([runtime, failing_test])

    assert diagnosis["status"] in {"CONFIRMED", "LIKELY"}
    assert diagnosis["bug_type"] == "runtime-error"
    assert diagnosis["reproduction_status"] == "REPRODUCED"
    assert diagnosis["primary_evidence"]
    assert diagnosis["root_cause_candidates"]
    assert diagnosis["root_cause_candidates"][0]["role"] == "ROOT_CAUSE"


def test_static_warning_is_not_confirmed_bug_without_runtime_evidence() -> None:
    static = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="luau-analyze",
        project_scope="project-root",
        message="Possible nil access",
        affected_files=["src/ServerScript.luau"],
        proof_strength="LOW",
        status="AVAILABLE",
        code_location="src/ServerScript.luau:7",
        severity="MEDIUM",
    )

    diagnosis = diagnose_evidence_group([static])

    assert diagnosis["status"] == "SUSPECTED"
    assert diagnosis["reproduction_status"] == "INCONCLUSIVE"
    assert diagnosis["fix_confidence"] == "LOW"


def test_diagnosis_keeps_contradictory_evidence() -> None:
    static = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="ruff",
        project_scope="project-root",
        message="Warning: suspicious import order",
        affected_files=["src/example.py"],
        proof_strength="NONE",
        status="UNAVAILABLE",
        availability_note="Tool unavailable in this environment.",
    )
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime failed in example.py",
        affected_files=["src/example.py"],
        proof_strength="MEDIUM",
        status="AVAILABLE",
    )
    contradiction = make_evidence_relationship(
        source_evidence_id=static["evidence_id"],
        target_evidence_id=runtime["evidence_id"],
        relationship_type="CONTRADICTS",
        reason="Tool unavailable conflicts with observed runtime evidence",
        signals=["availability_conflict"],
        strength="MEDIUM",
    )

    diagnosis = diagnose_evidence_group([static, runtime], relationships=[contradiction])

    assert static["evidence_id"] in diagnosis["contradictory_evidence"]
    assert diagnosis["status"] in {"CONFIRMED", "LIKELY"}


def test_diagnoses_persist_and_reference_real_evidence_ids() -> None:
    path = Path("logs/test_phase4_diagnoses.jsonl")
    if path.exists():
        path.unlink()

    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime error in server code",
        affected_files=["src/server.lua"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="src/server.lua:10",
        run_id="run-700",
    )
    static = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="luau-analyze",
        project_scope="project-root",
        message="Possible nil access",
        affected_files=["src/server.lua"],
        proof_strength="LOW",
        status="AVAILABLE",
        code_location="src/server.lua:10",
        run_id="run-700",
    )

    diagnosis_records = diagnose_evidence_records([runtime, static], path=path)
    persisted = read_diagnosis_records(path)

    assert len(diagnosis_records) == 1
    assert len(persisted) == 1
    assert diagnosis_records[0]["primary_evidence"][0] == runtime["evidence_id"]
    assert persisted[0]["issue_id"] == diagnosis_records[0]["issue_id"]


def test_ai_payload_parser_validates_and_normalizes_structured_output() -> None:
    payload = {
        "bug_type": "runtime-error",
        "status": "LIKELY",
        "evidence_strength": "HIGH",
        "diagnostic_confidence": "MEDIUM",
        "fix_confidence": "LOW",
        "severity": "HIGH",
        "reproduction_status": "REPRODUCED",
        "symptom": "A request fails when the value is null.",
        "trigger": "The function does not guard for null state.",
        "affected_files": ["src/service.py"],
        "affected_locations": ["src/service.py:42"],
        "contradictory_evidence": ["ev-contradict"],
        "contributing_factors": ["Missing guard"],
        "root_cause_candidates": [
            {
                "role": "ROOT_CAUSE",
                "summary": "Missing guard before dereference.",
                "evidence_ids": ["ev-1"],
                "confidence": "HIGH",
            }
        ],
        "selected_root_cause": "Missing guard before dereference.",
        "recommended_validation": ["Reproduce with the failing test"],
    }

    parsed = normalize_ai_diagnosis_payload(payload, issue_id="issue-42", evidence_ids=["ev-1", "ev-2"])

    assert parsed is not None
    assert parsed["status"] == "LIKELY"
    assert parsed["root_cause_candidates"][0]["role"] == "ROOT_CAUSE"
    assert parsed["selected_root_cause"] == "Missing guard before dereference."


def test_diagnosis_generates_candidate_fix_with_provenance_and_evidence() -> None:
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="AttributeError: 'NoneType' object has no attribute 'value'",
        affected_files=["src/service.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="src/service.py:42",
        severity="HIGH",
        run_id="run-900",
    )
    test_failure = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name="pytest",
        project_scope="project-root",
        message="AssertionError in test_service",
        affected_files=["src/service.py", "tests/test_service.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="tests/test_service.py:12",
        severity="HIGH",
        run_id="run-900",
    )

    diagnosis = diagnose_evidence_group([runtime, test_failure])
    diagnosis["diagnostic_confidence"] = "HIGH"
    diagnosis["fix_confidence"] = "LOW"
    fixes = generate_candidate_fixes_from_diagnosis(diagnosis, evidence_records=[runtime, test_failure])

    assert fixes
    assert diagnosis["candidate_fixes"]
    assert diagnosis["diagnostic_confidence"] != diagnosis["fix_confidence"]
    assert fixes[0]["diagnosis_id"] == diagnosis["diagnosis_id"]
    assert fixes[0]["issue_id"] == diagnosis["issue_id"]
    assert diagnosis["primary_evidence"] == [runtime["evidence_id"]]
    assert runtime["evidence_id"] in fixes[0]["primary_evidence"]
    assert test_failure["evidence_id"] in fixes[0]["supporting_evidence"]
    assert fixes[0]["root_cause_summary"]
    assert fixes[0]["confidence"] == diagnosis["fix_confidence"]
    assert fixes[0]["constraints"]


def test_inconclusive_diagnosis_yields_needs_more_evidence_fix() -> None:
    static = make_evidence_record(
        evidence_type="STATIC_WARNING",
        tool_name="luau-analyze",
        project_scope="project-root",
        message="Possible nil access without a confirmed reproducer.",
        affected_files=["src/ServerScript.luau"],
        proof_strength="LOW",
        status="AVAILABLE",
        code_location="src/ServerScript.luau:7",
        severity="MEDIUM",
    )

    diagnosis = diagnose_evidence_group([static])
    fixes = generate_candidate_fixes_from_diagnosis(diagnosis, evidence_records=[static])

    assert fixes
    assert fixes[0]["status"] == "NEEDS_MORE_EVIDENCE"
    assert "No code changes are proposed" in fixes[0]["proposed_change"]
    assert fixes[0]["confidence"] == "LOW"


def test_multiple_candidate_fixes_can_be_generated_and_persisted() -> None:
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime value is None during deserialization.",
        affected_files=["src/loader.py"],
        proof_strength="MEDIUM",
        status="AVAILABLE",
        code_location="src/loader.py:12",
        severity="HIGH",
        run_id="run-910",
    )
    config = make_evidence_record(
        evidence_type="CONFIGURATION_PROBLEM",
        tool_name="config-check",
        project_scope="project-root",
        message="Missing required configuration value in environment.",
        affected_files=["src/loader.py", "config/defaults.json"],
        proof_strength="MEDIUM",
        status="AVAILABLE",
        code_location="config/defaults.json:1",
        severity="MEDIUM",
        run_id="run-910",
    )

    diagnosis = diagnose_evidence_group([runtime, config])
    diagnosis["root_cause_candidates"] = [
        {
            "role": "ROOT_CAUSE",
            "summary": "Missing runtime guard before deserialization.",
            "evidence_ids": [runtime["evidence_id"]],
            "confidence": "HIGH",
        },
        {
            "role": "TRIGGER",
            "summary": "Missing configuration causes the null runtime state.",
            "evidence_ids": [config["evidence_id"]],
            "confidence": "MEDIUM",
        },
    ]
    diagnosis["fix_confidence"] = "MEDIUM"

    fixes = generate_candidate_fixes_from_diagnosis(diagnosis, evidence_records=[runtime, config])
    assert len(fixes) == 2
    assert {fix["status"] for fix in fixes} <= {"PROPOSED", "REVIEWED", "NEEDS_MORE_EVIDENCE"}

    fix_path = Path("logs/test_candidate_fix_pipeline.jsonl")
    if fix_path.exists():
        fix_path.unlink()
    analysis_path = Path("logs/test_candidate_fix_analysis_pipeline.jsonl")
    if analysis_path.exists():
        analysis_path.unlink()

    for fix in fixes:
        append_candidate_fix_record(fix_path, fix)
        append_fix_analysis_record(analysis_path, analyze_candidate_fix(fix, diagnosis=diagnosis))

    rows = read_candidate_fix_records(fix_path)
    assert len(rows) == 2
    assert len(read_fix_analysis_records(analysis_path)) == 2


def test_candidate_fix_integration_writes_diagnosis_links_and_persists() -> None:
    runtime = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name="runtime-monitor",
        project_scope="project-root",
        message="Runtime failure in session manager",
        affected_files=["src/session.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        code_location="src/session.py:18",
        severity="HIGH",
        run_id="run-920",
    )

    diagnosis_path = Path("logs/test_candidate_fix_integration_diagnoses.jsonl")
    if diagnosis_path.exists():
        diagnosis_path.unlink()
    candidate_path = Path("logs/candidate_fixes.jsonl")
    if candidate_path.exists():
        candidate_path.unlink()
    analysis_path = Path("logs/fix_analyses.jsonl")
    if analysis_path.exists():
        analysis_path.unlink()

    diagnoses = diagnose_evidence_records([runtime], path=diagnosis_path)
    fix_records = read_candidate_fix_records(candidate_path)
    assert diagnoses and diagnoses[0]["candidate_fixes"]
    assert fix_records
    assert fix_records[0]["diagnosis_id"] == diagnoses[0]["diagnosis_id"]
    assert fix_records[0]["issue_id"] == diagnoses[0]["issue_id"]
    assert len(read_fix_analysis_records(analysis_path)) == len(fix_records)
