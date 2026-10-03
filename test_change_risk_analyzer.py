from __future__ import annotations

import json

import pytest

from change_risk_analyzer import (
    ChangeRiskAssessment,
    DiagnosisEvidence,
    ExplicitProjectEvidence,
    analyze_change_risk,
    parse_change_risk_assessment,
)
from validation_analyzer import (
    TestFailure as FailureRecord,
    TestResult as RunResultRecord,
    TestRunStatus as RunStatus,
)


RUN_ID = "originating-test-run"


def make_diagnosis(
    files: list[str] | None = None,
    *,
    change_size: str = "SMALL",
    exact_file: str | None = "src/module.py",
    diagnosis_file: str | None = "src/module.py",
    evidence: list[str] | None = None,
) -> DiagnosisEvidence:
    affected_files = files if files is not None else ["src/module.py"]
    return {
        "confidence": "HIGH",
        "diagnosis": "A test fails for the observed value.",
        "likely_cause": "The value is inconsistent.",
        "proposed_change": "Update the value.",
        "change_size": change_size,
        "affected_files": affected_files,
        "file": diagnosis_file,
        "exact_change": {
            "file": exact_file,
            "line": 4,
            "old_text": "old",
            "new_text": "new",
        },
        "evidence": evidence if evidence is not None else ["Observed failure."],
    }


def make_test_result(
    run_id: str = RUN_ID,
    *,
    status: RunStatus = "FAILED",
    failures: list[FailureRecord] | None = None,
) -> RunResultRecord:
    failure_values = (
        failures
        if failures is not None
        else [
            {
                "file": "src/module.py",
                "line": 4,
                "test": "test_module",
            }
        ]
    )
    return {
        "run_id": run_id,
        "status": status,
        "command": ["python", "-m", "pytest"],
        "failures": failure_values,
    }


def make_complete_project_evidence(
    files: list[str] | None = None,
    *,
    core_files: list[str] | None = None,
    subsystems: dict[str, str] | None = None,
) -> ExplicitProjectEvidence:
    affected_files = files if files is not None else ["src/module.py"]
    return {
        "coverage_complete": True,
        "core_infrastructure_files": core_files or [],
        "subsystem_by_file": (
            subsystems
            if subsystems is not None
            else {file_path: "application" for file_path in affected_files}
        ),
    }


def test_low_risk_requires_complete_explicit_evidence() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "LOW"
    assert assessment["originating_run_id"] == RUN_ID
    assert assessment["test_status"] == "FAILED"
    assert assessment["test_command"] == ["python", "-m", "pytest"]
    assert any(
        item["factor"] == "core_infrastructure_involvement"
        and item["state"] == "ABSENT"
        for item in assessment["evidence"]
    )
    assert any(
        item["factor"] == "changed_line_count"
        and item["state"] == "UNKNOWN"
        for item in assessment["evidence"]
    )


def test_medium_risk_for_two_to_four_proposed_files() -> None:
    diagnosis = make_diagnosis(
        ["src/one.py", "src/two.py"],
        exact_file="src/one.py",
        diagnosis_file="src/one.py",
    )
    project_evidence = make_complete_project_evidence(
        ["src/one.py", "src/two.py"]
    )

    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(failures=[{"file": "src/one.py", "line": 4}]),
        project_evidence,
    )

    assert assessment["level"] == "MEDIUM"
    assert any(
        "diagnosis-provided proposed scope lists 2" in reason
        for reason in assessment["reasons"]
    )


def test_medium_risk_for_diagnosis_reported_medium_change_size() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(change_size="MEDIUM"),
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "MEDIUM"
    assert any(
        "diagnosis labels the proposed change MEDIUM" in reason
        for reason in assessment["reasons"]
    )


def test_medium_risk_for_test_file_in_proposed_scope() -> None:
    diagnosis = make_diagnosis(
        ["tests/test_module.py"],
        exact_file="tests/test_module.py",
        diagnosis_file="tests/test_module.py",
    )
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(
            failures=[
                {"file": "tests/test_module.py", "line": 4, "test": "test_it"}
            ]
        ),
        make_complete_project_evidence(["tests/test_module.py"]),
    )

    assert assessment["level"] == "MEDIUM"
    assert any(
        item["factor"] == "test_file_involvement"
        and item["state"] == "PRESENT"
        for item in assessment["evidence"]
    )


def test_high_risk_for_five_diagnosis_provided_files() -> None:
    files = [f"src/file_{index}.py" for index in range(5)]
    diagnosis = make_diagnosis(
        files,
        exact_file=files[0],
        diagnosis_file=files[0],
    )
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(failures=[{"file": files[0], "line": 4}]),
    )

    assert assessment["level"] == "HIGH"
    assert any(
        "diagnosis-provided proposed scope lists 5 unique files"
        in reason
        and "not an observed changed-file count" in reason
        for reason in assessment["reasons"]
    )


def test_high_risk_for_diagnosis_reported_large_change() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(change_size="LARGE"),
        RUN_ID,
        make_test_result(),
    )

    assert assessment["level"] == "HIGH"
    assert any(
        "diagnosis labels the proposed change LARGE" in reason
        and "not an independently measured diff" in reason
        for reason in assessment["reasons"]
    )


@pytest.mark.parametrize(
    "path",
    [
        "pyproject.toml",
        "requirements-dev.txt",
        "package-lock.json",
        "config/application.yaml",
        "overseer.json",
    ],
)
def test_high_risk_for_recognized_configuration_or_dependency_path(
    path: str,
) -> None:
    assessment = analyze_change_risk(
        make_diagnosis(
            [path],
            exact_file=path,
            diagnosis_file=path,
        ),
        RUN_ID,
        make_test_result(failures=[{"file": path, "line": 1}]),
    )

    assert assessment["level"] == "HIGH"
    assert any(
        item["factor"] == "configuration_or_dependency_involvement"
        and item["source"] == "DIAGNOSIS_PROVIDED"
        and item["state"] == "PRESENT"
        for item in assessment["evidence"]
    )


def test_high_risk_for_exact_target_outside_diagnosis_scope() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(
            ["src/module.py"],
            exact_file="src/other.py",
            diagnosis_file="src/module.py",
        ),
        RUN_ID,
        make_test_result(),
    )

    assert assessment["level"] == "HIGH"
    assert any(
        item["factor"] == "diagnosis_and_proposed_scope_consistency"
        and item["state"] == "CONFLICTING"
        for item in assessment["evidence"]
    )


def test_high_risk_for_explicit_core_infrastructure_evidence() -> None:
    evidence = make_complete_project_evidence(
        core_files=["src/module.py"],
    )
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
        evidence,
    )

    assert assessment["level"] == "HIGH"
    assert any(
        "Explicit project evidence identifies core/infrastructure"
        in reason
        for reason in assessment["reasons"]
    )


def test_high_risk_for_explicit_cross_subsystem_evidence() -> None:
    files = ["src/one.py", "src/two.py"]
    evidence = make_complete_project_evidence(
        files,
        subsystems={"src/one.py": "runtime", "src/two.py": "storage"},
    )
    diagnosis = make_diagnosis(
        files,
        exact_file="src/one.py",
        diagnosis_file="src/one.py",
    )
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(failures=[{"file": "src/one.py", "line": 4}]),
        evidence,
    )

    assert assessment["level"] == "HIGH"
    assert any(
        "cross-subsystem proposed change" in reason
        for reason in assessment["reasons"]
    )


def test_unknown_for_conflicting_subsystem_evidence() -> None:
    evidence: ExplicitProjectEvidence = {
        "coverage_complete": True,
        "core_infrastructure_files": [],
        "subsystem_by_file": {
            "src/module.py": "runtime",
            "./src/module.py": "storage",
        },
    }
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
        evidence,
    )

    assert assessment["level"] == "UNKNOWN"
    assert any(
        "subsystem evidence conflicts" in item
        for item in assessment["uncertainties"]
    )


def test_unknown_when_test_status_conflicts_with_failure_records() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(status="PASSED"),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "UNKNOWN"
    assert any(
        item["factor"] == "originating_test_run_consistency"
        and item["state"] == "CONFLICTING"
        for item in assessment["evidence"]
    )


def test_unknown_when_project_classification_is_missing() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
    )

    assert assessment["level"] == "UNKNOWN"
    assert any(
        "Core/infrastructure" in item
        for item in assessment["uncertainties"]
    )
    assert any(
        "not treated as low risk" in item
        for item in assessment["reasons"]
    )


def test_unknown_when_originating_test_is_unavailable() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        None,
        make_complete_project_evidence(),
        test_result_issue="Test log could not be read.",
    )

    assert assessment["level"] == "UNKNOWN"
    assert assessment["test_status"] is None
    assert assessment["test_result_issue"] == "Test log could not be read."
    assert any(
        "originating run ID" in item
        for item in assessment["uncertainties"]
    )


def test_unknown_when_test_result_run_id_conflicts() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result("different-run"),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "UNKNOWN"
    assert any("conflicts" in item for item in assessment["uncertainties"])
    assert assessment["test_status"] is None


def test_unknown_when_relevant_failure_is_not_established() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(
            failures=[{"file": "elsewhere.py", "line": 4, "test": "test_else"}]
        ),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "UNKNOWN"
    assert assessment["relevant_test_failures"] == []
    assert any(
        "test relevance is unestablished" in item
        for item in assessment["uncertainties"]
    )


def test_unknown_when_project_evidence_does_not_cover_every_file() -> None:
    files = ["src/one.py", "src/two.py"]
    diagnosis = make_diagnosis(
        files,
        exact_file="src/one.py",
        diagnosis_file="src/one.py",
    )
    project_evidence: ExplicitProjectEvidence = {
        "coverage_complete": True,
        "core_infrastructure_files": [],
        "subsystem_by_file": {"src/one.py": "runtime"},
    }
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(failures=[{"file": "src/one.py", "line": 4}]),
        project_evidence,
    )

    assert assessment["level"] == "MEDIUM"
    assert any(
        "subsystem classification" in item
        for item in assessment["uncertainties"]
    )


def test_unknown_when_file_type_cannot_be_classified() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(
            ["opaque"],
            exact_file="opaque",
            diagnosis_file="opaque",
        ),
        RUN_ID,
        make_test_result(failures=[{"file": "opaque", "line": 1}]),
        make_complete_project_evidence(["opaque"]),
    )

    assert assessment["level"] == "UNKNOWN"
    assert any("file types" in item for item in assessment["uncertainties"])


def test_unknown_when_diagnosis_reports_low_confidence() -> None:
    diagnosis = make_diagnosis()
    diagnosis["confidence"] = "LOW"
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(),
    )

    assert assessment["level"] == "UNKNOWN"
    assert any("LOW confidence" in item for item in assessment["uncertainties"])


def test_scope_is_deduplicated_and_never_described_as_actual() -> None:
    diagnosis = make_diagnosis(
        [
            "./src/module.py",
            "src\\module.py",
            "src/../src/module.py",
        ],
        exact_file="src/module.py",
        diagnosis_file="src/module.py",
    )
    assessment = analyze_change_risk(
        diagnosis,
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(["src/module.py"]),
    )

    count_item = next(
        item
        for item in assessment["evidence"]
        if item["factor"] == "affected_file_count"
    )
    assert "1 unique file" in count_item["detail"]
    assert count_item["source"] == "DIAGNOSIS_PROVIDED"
    assert "not actual changed files" in count_item["detail"]


def test_diagnosis_evidence_is_provenance_labelled() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(),
    )

    source_item = next(
        item
        for item in assessment["evidence"]
        if item["factor"] == "diagnosis_evidence"
    )
    assert source_item["source"] == "DIAGNOSIS_PROVIDED"
    assert "preserved in the assessment" in source_item["detail"]
    assert assessment["diagnosis_evidence"] == ["Observed failure."]
    assert any(
        item["factor"] == "proposal_diagnosis_link"
        and "does not independently establish" in item["detail"]
        for item in assessment["evidence"]
    )
    assert any(
        "causal link" in item
        for item in assessment["uncertainties"]
    )
    assert any(
        item["source"] == "VERIFIED_TEST_RUN"
        and RUN_ID in item["detail"]
        for item in assessment["evidence"]
    )


def test_reasons_are_deterministic() -> None:
    diagnosis = make_diagnosis(["pyproject.toml"], exact_file="pyproject.toml")
    result = make_test_result(
        failures=[{"file": "pyproject.toml", "line": 4}]
    )
    first = analyze_change_risk(diagnosis, RUN_ID, result)
    second = analyze_change_risk(diagnosis, RUN_ID, result)

    assert first == second


def test_assessment_json_round_trip_and_rejects_invalid_shape() -> None:
    assessment = analyze_change_risk(
        make_diagnosis(),
        RUN_ID,
        make_test_result(),
        make_complete_project_evidence(),
    )
    encoded = json.loads(json.dumps(assessment))

    assert parse_change_risk_assessment(encoded) == assessment
    assert parse_change_risk_assessment({"level": "LOW"}) is None
