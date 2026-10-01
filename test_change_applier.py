from pathlib import Path

import pytest

import change_applier


PROJECT_FOLDER = Path(__file__).resolve().parent
TEST_FILE = PROJECT_FOLDER / "rollback_target.txt"


def test_apply_change_rolls_back_when_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_content = "original value\n"
    new_content = "changed value\n"

    TEST_FILE.write_text(
        original_content,
        encoding="utf-8",
    )

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "test-run-id",
        "timestamp": "test-diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test rollback",
            "likely_cause": "Test rollback",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Test rollback",
            "proposed_change": "Change original value",
            "affected_files": [
                "rollback_target.txt",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": new_content,
            },
        },
    }

    def failed_validation(
        _run_id: str,
    ) -> bool:
        return False

    monkeypatch.setattr(
        change_applier,
        "run_post_change_validation",
        failed_validation,
    )

    try:
        success = change_applier.apply_change(
            diagnosis
        )

        assert success is False

        restored_content = TEST_FILE.read_text(
            encoding="utf-8",
        )

        assert restored_content == original_content

    finally:
        if TEST_FILE.exists():
            TEST_FILE.unlink()


def test_permission_with_different_run_id_is_rejected() -> None:
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "test_failure.py",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Test next step",
            "proposed_change": "Test change",
            "affected_files": [
                "test_failure.py",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "test_failure.py",
                "line": 1,
                "old_text": "old",
                "new_text": "new",
            },
        },
    }

    permission: change_applier.PermissionRecord = {
        "run_id": "different-run-id",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "test_failure.py",
        "line": 1,
        "proposed_change": "Test change",
        "affected_files": [
            "test_failure.py",
        ],
        "change_size": "SMALL",
        "exact_change": {
            "file": "test_failure.py",
            "line": 1,
            "old_text": "old",
            "new_text": "new",
        },
    }

    assert (
        change_applier.permission_matches_diagnosis(
            diagnosis,
            permission,
        )
        is False
    )


def test_rejected_permission_cannot_authorize_change() -> None:
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "same-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "test_failure.py",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Test next step",
            "proposed_change": "Test change",
            "affected_files": [
                "test_failure.py",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "test_failure.py",
                "line": 1,
                "old_text": "old",
                "new_text": "new",
            },
        },
    }

    permission: change_applier.PermissionRecord = {
        "run_id": "same-run-id",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "REJECTED",
        "file": "test_failure.py",
        "line": 1,
        "proposed_change": "Test change",
        "affected_files": [
            "test_failure.py",
        ],
        "change_size": "SMALL",
        "exact_change": {
            "file": "test_failure.py",
            "line": 1,
            "old_text": "old",
            "new_text": "new",
        },
    }

    assert (
        change_applier.can_apply_change(
            diagnosis,
            permission,
        )
        is False
    )


def test_changed_diagnosis_cannot_use_old_permission() -> None:
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "same-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "test_failure.py",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Test next step",
            "proposed_change": "New change",
            "affected_files": [
                "test_failure.py",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "test_failure.py",
                "line": 1,
                "old_text": "old",
                "new_text": "new",
            },
        },
    }

    permission: change_applier.PermissionRecord = {
        "run_id": "same-run-id",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "test_failure.py",
        "line": 1,
        "proposed_change": "Old change",
        "affected_files": [
            "test_failure.py",
        ],
        "change_size": "SMALL",
        "exact_change": {
            "file": "test_failure.py",
            "line": 1,
            "old_text": "old",
            "new_text": "new",
        },
    }

    assert (
        change_applier.permission_matches_diagnosis(
            diagnosis,
            permission,
        )
        is False
    )


def test_missing_run_id_is_rejected_when_parsing_records() -> None:
    diagnosis: dict[object, object] = {
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "test_failure.py",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Test next step",
            "proposed_change": "Test change",
            "affected_files": [
                "test_failure.py",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "test_failure.py",
                "line": 1,
                "old_text": "old",
                "new_text": "new",
            },
        },
    }

    permission: dict[object, object] = {
        "run_id": "",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "test_failure.py",
        "line": 1,
        "proposed_change": "Test change",
        "affected_files": [
            "test_failure.py",
        ],
        "change_size": "SMALL",
        "exact_change": {
            "file": "test_failure.py",
            "line": 1,
            "old_text": "old",
            "new_text": "new",
        },
    }

    assert (
        change_applier.parse_diagnosis(
            diagnosis
        )
        is None
    )

    assert (
        change_applier.parse_permission(
            permission
        )
        is None
    )


def test_approved_permission_allows_change_after_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_content = "original value\n"
    new_content = "changed value\n"

    TEST_FILE.write_text(
        original_content,
        encoding="utf-8",
    )

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "integration-run-id",
        "timestamp": "integration-diagnosis-time",
        "test_timestamp": "integration-test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration test diagnosis",
            "likely_cause": "Integration test cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply integration test change",
            "proposed_change": "Change original value",
            "affected_files": [
                "rollback_target.txt",
            ],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": new_content,
            },
        },
    }

    permission: change_applier.PermissionRecord = {
        "run_id": "integration-run-id",
        "diagnosis_timestamp": "integration-diagnosis-time",
        "permission_timestamp": "integration-permission-time",
        "decision": "APPROVED",
        "file": "rollback_target.txt",
        "line": 1,
        "proposed_change": "Change original value",
        "affected_files": [
            "rollback_target.txt",
        ],
        "change_size": "SMALL",
        "exact_change": {
            "file": "rollback_target.txt",
            "line": 1,
            "old_text": original_content,
            "new_text": new_content,
        },
    }

    def successful_validation(
        _run_id: str,
    ) -> bool:
        return True

    monkeypatch.setattr(
        change_applier,
        "run_post_change_validation",
        successful_validation,
    )

    try:
        assert (
            change_applier.can_apply_change(
                diagnosis,
                permission,
            )
            is True
        )

        success = change_applier.apply_change(
            diagnosis
        )

        assert success is True

        changed_content = TEST_FILE.read_text(
            encoding="utf-8",
        )

        assert changed_content == new_content

    finally:
        if TEST_FILE.exists():
            TEST_FILE.unlink()