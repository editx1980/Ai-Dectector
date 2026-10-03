from __future__ import annotations

from pathlib import Path

from evidence_models import (
    CandidateFixRecord,
    DiagnosisRecord,
    EvidenceRecord,
    append_candidate_fix_record,
    append_diagnosis_record,
    append_evidence_record,
    append_fix_analysis_record,
    analyze_candidate_fix,
    make_candidate_fix_record,
    make_diagnosis_record,
    make_evidence_record,
    make_fix_analysis_record,
    read_candidate_fix_records,
    read_diagnosis_records,
    read_evidence_records,
    read_fix_analysis_records,
)


def test_evidence_record_persists_and_keeps_separate_fields() -> None:
    path = Path("logs/test_evidence_model.jsonl")
    if path.exists():
        path.unlink()

    record = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name="pytest",
        project_scope="project-root",
        message="Assertion failed in integration test",
        affected_files=["src/app.py"],
        proof_strength="HIGH",
        status="AVAILABLE",
        severity="HIGH",
        run_id="run-001",
        transaction_id="txn-001",
        correlation_keys=["issue:login"],
        related_evidence_ids=["old-evidence-1"],
    )

    stored = append_evidence_record(path, record)
    rows = read_evidence_records(path)

    assert stored["evidence_id"] == rows[0]["evidence_id"]
    assert rows[0]["evidence_type"] == "TEST_FAILURE"
    assert rows[0]["proof_strength"] == "HIGH"
    assert rows[0]["status"] == "AVAILABLE"
    assert rows[0]["severity"] == "HIGH"
    assert rows[0]["run_id"] == "run-001"
    assert rows[0]["transaction_id"] == "txn-001"


def test_diagnosis_tracks_confidence_dimensions_separately() -> None:
    record = make_diagnosis_record(
        issue_id="issue-1",
        bug_type="null-state-regression",
        status="LIKELY",
        evidence_strength="HIGH",
        diagnostic_confidence="MEDIUM",
        fix_confidence="LOW",
        severity="HIGH",
        reproduction_status="REPRODUCED",
        affected_files=["src/service.py"],
        affected_locations=["src/service.py:42"],
        primary_evidence=["ev-1"],
        supporting_evidence=["ev-2"],
        contradictory_evidence=[],
        symptom="A request fails when the validator returns null.",
        trigger="A missing guard allows a null value to reach validation.",
        contributing_factors=["state was not validated before use"],
        root_cause_candidates=[
            {
                "role": "ROOT_CAUSE",
                "summary": "Missing validation before dereference.",
                "evidence_ids": ["ev-1"],
                "confidence": "HIGH",
            },
            {
                "role": "CONTRIBUTING_FACTOR",
                "summary": "State can reach this path without a guard.",
                "evidence_ids": ["ev-2"],
                "confidence": "MEDIUM",
            },
        ],
        selected_root_cause="Missing validation before dereference.",
        introduced_by_change=True,
        dependency_context=["runtime-validator"],
        configuration_context=["prod-config"],
        historical_occurrences=["issue-older"],
        candidate_fixes=["fix-1"],
        recommended_validation=["run failing integration test"],
    )

    assert record["evidence_strength"] == "HIGH"
    assert record["diagnostic_confidence"] == "MEDIUM"
    assert record["fix_confidence"] == "LOW"
    assert record["severity"] == "HIGH"
    assert record["root_cause_candidates"][0]["role"] == "ROOT_CAUSE"
    assert record["selected_root_cause"] == "Missing validation before dereference."


def test_candidate_fix_record_round_trip() -> None:
    path = Path("logs/test_candidate_fix_model.jsonl")
    if path.exists():
        path.unlink()

    record = make_candidate_fix_record(
        diagnosis_id="diag-1",
        description="Add a guard for null state before validation.",
        proposed_change="Return an empty default when state is null.",
        affected_files=["src/service.py"],
        expected_effect="Prevents null dereference while maintaining previous behavior.",
        assumptions=["The downstream system expects a safe default."],
        supporting_evidence=["ev-1"],
        risk="MEDIUM",
        scope="single function",
        validation_plan=["Run the failing test", "Run related integration tests"],
        confidence="MEDIUM",
    )

    stored = append_candidate_fix_record(path, record)
    rows = read_candidate_fix_records(path)

    assert stored["fix_id"] == rows[0]["fix_id"]
    assert rows[0]["confidence"] == "MEDIUM"
    assert rows[0]["scope"] == "single function"


def test_fix_analysis_record_round_trip_and_statusing() -> None:
    fix_path = Path("logs/test_fix_analysis_model.jsonl")
    if fix_path.exists():
        fix_path.unlink()

    fix = make_candidate_fix_record(
        diagnosis_id="diag-2",
        description="Guard a null input before validation.",
        proposed_change="Handle null by returning the default value.",
        affected_files=["src/service.py"],
        expected_effect="Stops null dereference and keeps request handling safe.",
        assumptions=["The default value is acceptable for null input."],
        supporting_evidence=["ev-2"],
        risk="LOW",
        scope="single branch",
        validation_plan=["Run the relevant failing test"],
        confidence="HIGH",
        issue_id="issue-2",
    )
    analysis = analyze_candidate_fix(fix)
    stored = append_fix_analysis_record(fix_path, analysis)
    rows = read_fix_analysis_records(fix_path)

    assert stored["analysis_id"] == rows[0]["analysis_id"]
    assert rows[0]["status"] == "ACCEPTED"
    assert rows[0]["risk"] == "LOW"
    assert rows[0]["confidence"] == "HIGH"


def test_fix_analysis_factory_preserves_metadata() -> None:
    record = make_fix_analysis_record(
        fix_id="fix-42",
        diagnosis_id="diag-42",
        summary="A minimal guard is low risk and backed by runtime evidence.",
        risk="MEDIUM",
        confidence="MEDIUM",
        assumptions=["Null values should be treated as empty state."],
        counter_evidence=["No contradictory runtime evidence found."],
        validation_plan=["Run the failing test"],
        concerns=["Requires verifying downstream behavior."],
        issue_id="issue-42",
        status="REVIEWED",
    )

    assert record["status"] == "REVIEWED"
    assert record["issue_id"] == "issue-42"
    assert record["validation_plan"] == ["Run the failing test"]


def test_append_is_additive_not_overwrite() -> None:
    path = Path("logs/test_evidence_append_model.jsonl")
    if path.exists():
        path.unlink()

    append_evidence_record(
        path,
        make_evidence_record(
            evidence_type="STATIC_WARNING",
            tool_name="ruff",
            project_scope="project-root",
            message="Unused import",
            proof_strength="LOW",
            status="AVAILABLE",
        ),
    )
    append_evidence_record(
        path,
        make_evidence_record(
            evidence_type="STATIC_WARNING",
            tool_name="ruff",
            project_scope="project-root",
            message="Another warning",
            proof_strength="LOW",
            status="AVAILABLE",
        ),
    )

    rows = read_evidence_records(path)
    assert len(rows) == 2
    assert rows[0]["message"] != rows[1]["message"]


def test_tool_unavailable_is_distinct_from_no_issue() -> None:
    record = make_evidence_record(
        evidence_type="TYPE_ERROR",
        tool_name="pyright",
        project_scope="project-root",
        message="Tool unavailable in this environment",
        proof_strength="NONE",
        status="UNAVAILABLE",
        availability_note="Interpreter not configured for workspace.",
    )

    assert record["status"] == "UNAVAILABLE"
    assert record["proof_strength"] == "NONE"
    assert "Interpreter not configured" in record["availability_note"]
