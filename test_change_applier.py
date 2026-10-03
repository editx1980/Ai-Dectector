import json
import subprocess
from pathlib import Path

import pytest

import change_applier
import change_transaction


PROJECT_FOLDER = Path(__file__).resolve().parent
TEST_FILE = PROJECT_FOLDER / "rollback_target.txt"


def make_approved_permission(
    diagnosis: change_applier.DiagnosisRecord,
) -> change_applier.PermissionRecord:
    diagnosis_data = diagnosis["diagnosis"]
    return {
        "run_id": diagnosis["run_id"],
        "diagnosis_timestamp": diagnosis["timestamp"],
        "permission_timestamp": "test-permission-time",
        "decision": "APPROVED",
        "file": diagnosis_data["file"],
        "line": diagnosis_data["line"],
        "proposed_change": diagnosis_data["proposed_change"],
        "affected_files": diagnosis_data["affected_files"],
        "change_size": diagnosis_data["change_size"],
        "exact_change": diagnosis_data["exact_change"],
    }


def prepare_approved_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    diagnosis: change_applier.DiagnosisRecord,
    permission: change_applier.PermissionRecord,
    log_path: Path | None = None,
) -> str:
    transaction_log = (
        log_path
        if log_path is not None
        else tmp_path / "logs" / "change_transactions.jsonl"
    )
    monkeypatch.setattr(
        change_applier,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_log,
    )
    transaction = change_transaction.create_transaction(
        diagnosis["run_id"],
        diagnosis["run_id"],
        transaction_log,
    )
    transaction_id = transaction["transaction_id"]
    diagnosis["transaction_id"] = transaction_id
    permission["transaction_id"] = transaction_id

    change_transaction.transition_transaction(
        transaction_id,
        "PROPOSED",
        "AWAITING_PERMISSION",
        {"diagnosis_timestamp": diagnosis["timestamp"]},
        transaction_log,
    )
    change_transaction.transition_transaction(
        transaction_id,
        "AWAITING_PERMISSION",
        "APPROVED",
        {
            "permission_timestamp": permission["permission_timestamp"],
            "permission_decision": "APPROVED",
            "affected_files": permission["affected_files"],
        },
        transaction_log,
    )
    return transaction_id


def test_apply_change_rolls_back_when_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
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
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )

    def failed_validation(
        _run_id: str,
        _affected_files: list[str],
    ) -> change_applier.PostChangeValidationResult:
        return {
            "previous_run_id": _run_id,
            "post_change_run_id": "new-run-id",
            "post_change_test_status": "FAILED",
            "change_aware_validation_status": "FAILED",
            "validation_evidence": ["Simulated failed validation."],
        }

    monkeypatch.setattr(
        change_applier,
        "analyze_post_change_validation",
        failed_validation,
    )
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        tmp_path / "logs" / "validation_results.jsonl",
    )

    try:
        success = change_applier.apply_change(
            diagnosis,
            permission,
            transaction_id,
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
    tmp_path: Path,
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
        _affected_files: list[str],
    ) -> change_applier.PostChangeValidationResult:
        return {
            "previous_run_id": _run_id,
            "post_change_run_id": "new-run-id",
            "post_change_test_status": "PASSED",
            "change_aware_validation_status": "PASSED",
            "validation_evidence": ["Validation passed."],
        }

    monkeypatch.setattr(
        change_applier,
        "analyze_post_change_validation",
        successful_validation,
    )
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        tmp_path / "logs" / "validation_results.jsonl",
    )
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
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
            diagnosis,
            permission,
            transaction_id,
        )

        assert success is True

        changed_content = TEST_FILE.read_text(
            encoding="utf-8",
        )

        assert changed_content == new_content

    finally:
        if TEST_FILE.exists():
            TEST_FILE.unlink()


def _prepare_real_tester_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    exit_code: int,
    previous_run_id: str,
    previous_failure_file: str = "rollback_target.txt",
) -> None:
    project_dir = tmp_path / "project"
    logs_dir = project_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    source_folder = Path(__file__).resolve().parent

    for file_name in ("tester.py", "runtime_monitor.py"):
        source_path = source_folder / file_name
        destination = project_dir / file_name
        destination.write_text(
            source_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )

    command_script = (
        "import sys; "
        f"sys.exit({exit_code})"
    )
    command = [
        "python",
        "-c",
        command_script,
    ]

    config_path = project_dir / "overseer.json"
    config_path.write_text(
        json.dumps(
            {
                "test_command": command,
            }
        ),
        encoding="utf-8",
    )

    test_result_path = logs_dir / "test_results.jsonl"
    test_result_path.write_text(
        json.dumps(
            {
                "run_id": previous_run_id,
                "status": "FAILED",
                "command": command,
                "failures": [
                    {
                        "file": previous_failure_file,
                        "line": 1,
                        "test": "test_original_failure",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "LOG_FOLDER",
        logs_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        project_dir / "tester.py",
    )
    monkeypatch.setattr(
        change_applier,
        "TEST_RESULTS_FILE",
        test_result_path,
    )
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        logs_dir / "validation_results.jsonl",
    )


def test_run_post_change_validation_accepts_new_passed_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="old-run-id",
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id",
            ["rollback_target.txt"],
        )
        is True
    )


def test_run_post_change_validation_rejects_failed_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=1,
        previous_run_id="old-run-id",
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id",
            ["rollback_target.txt"],
        )
        is False
    )


def test_run_post_change_validation_rejects_stale_run_id(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    logs_dir = project_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    tester_path = project_dir / "tester.py"
    tester_path.write_text(
        (Path(__file__).resolve().parent / "tester.py").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    test_result_path = logs_dir / "test_results.jsonl"
    test_result_path.write_text(
        json.dumps(
            {
                "run_id": "old-run-id",
                "status": "FAILED",
                "command": ["python", "-c", "pass"],
                "failures": [
                    {
                        "file": "rollback_target.txt",
                        "line": 1,
                        "test": "test_original_failure",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "LOG_FOLDER",
        logs_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        tester_path,
    )
    monkeypatch.setattr(
        change_applier,
        "TEST_RESULTS_FILE",
        test_result_path,
    )
    monkeypatch.setattr(
        change_applier,
        "get_latest_test_result",
        lambda: {
            "run_id": "old-run-id",
            "status": "PASSED",
            "command": ["python", "-c", "pass"],
            "failures": [],
        },
    )

    def fake_run(
        *args: object,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(
        change_applier.subprocess,
        "run",
        fake_run,
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id",
            ["rollback_target.txt"],
        )
        is False
    )


def test_run_post_change_validation_rejects_no_new_result(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    logs_dir = project_dir / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)

    tester_path = project_dir / "tester.py"
    tester_path.write_text(
        (Path(__file__).resolve().parent / "tester.py").read_text(
            encoding="utf-8"
        ),
        encoding="utf-8",
    )

    test_result_path = logs_dir / "test_results.jsonl"
    test_result_path.write_text(
        json.dumps(
            {
                "run_id": "old-run-id",
                "status": "FAILED",
                "command": ["python", "-c", "pass"],
                "failures": [
                    {
                        "file": "rollback_target.txt",
                        "line": 1,
                        "test": "test_original_failure",
                    }
                ],
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "LOG_FOLDER",
        logs_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        tester_path,
    )
    monkeypatch.setattr(
        change_applier,
        "TEST_RESULTS_FILE",
        test_result_path,
    )
    monkeypatch.setattr(
        change_applier,
        "get_latest_test_result",
        lambda: {
            "run_id": "old-run-id",
            "status": "PASSED",
            "command": ["python", "-c", "pass"],
            "failures": [],
        },
    )

    def fake_run(
        *args: object,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=0,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(
        change_applier.subprocess,
        "run",
        fake_run,
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id",
            ["rollback_target.txt"],
        )
        is False
    )


def test_run_post_change_validation_rejects_failed_subprocess(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    tester_path = project_dir / "tester.py"
    tester_path.write_text("print('test')\n", encoding="utf-8")

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        tester_path,
    )

    def fake_run(
        *args: object,
        **kwargs: object,
    ) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(
            args=args[0],
            returncode=1,
            stdout=b"",
            stderr=b"",
        )

    monkeypatch.setattr(
        change_applier.subprocess,
        "run",
        fake_run,
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id"
        )
        is False
    )


def test_run_post_change_validation_rejects_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    tester_path = project_dir / "tester.py"
    tester_path.write_text("print('test')\n", encoding="utf-8")

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        tester_path,
    )

    def raise_timeout(
        *args: object,
        **kwargs: object,
    ) -> None:
        raise subprocess.TimeoutExpired(
            cmd=["python", str(tester_path)],
            timeout=30,
        )

    monkeypatch.setattr(
        change_applier.subprocess,
        "run",
        raise_timeout,
    )

    assert (
        change_applier.run_post_change_validation(
            "old-run-id"
        )
        is False
    )


def test_apply_change_uses_real_validation_and_keeps_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }

    permission: change_applier.PermissionRecord = {
        "run_id": "diagnosis-run-id",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "rollback_target.txt",
        "line": 1,
        "proposed_change": "Use new content",
        "affected_files": ["rollback_target.txt"],
        "change_size": "SMALL",
        "exact_change": {
            "file": "rollback_target.txt",
            "line": 1,
            "old_text": original_content,
            "new_text": "changed value\n",
        },
    }

    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="diagnosis-run-id",
    )

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )

    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    assert change_applier.can_apply_change(diagnosis, permission) is True
    success = change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    )

    assert success is True
    assert target_path.read_text(encoding="utf-8") == "changed value\n"
    validation_record = json.loads(
        (project_dir / "logs" / "validation_results.jsonl").read_text(
            encoding="utf-8",
        ).strip()
    )
    latest_test_result = json.loads(
        (project_dir / "logs" / "test_results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[-1]
    )
    assert validation_record["previous_run_id"] == "diagnosis-run-id"
    assert validation_record["transaction_id"] == transaction_id
    assert validation_record["post_change_run_id"] == latest_test_result["run_id"]
    assert validation_record["post_change_run_id"] != "diagnosis-run-id"
    assert validation_record["change_aware_validation_status"] == "PASSED"
    assert validation_record["scope_validation_status"] == "PASSED"
    assert validation_record["final_validation_status"] == "PASSED"
    transaction_record = change_transaction.get_transaction(
        transaction_id,
        change_applier.CHANGE_TRANSACTIONS_FILE,
    )
    assert transaction_record is not None
    assert transaction_record["state"] == "SUCCEEDED"
    assert transaction_record["final_outcome"] == "SUCCESS"
    assert transaction_record["post_change_run_id"] == latest_test_result["run_id"]
    assert transaction_record["post_change_test_status"] == "PASSED"
    assert transaction_record["diagnosis_run_id"] == "diagnosis-run-id"
    assert transaction_record["pre_change_run_id"] == "diagnosis-run-id"
    assert transaction_record["change_aware_validation_status"] == "PASSED"
    assert transaction_record["scope_validation_status"] == "PASSED"
    assert transaction_record["actual_changed_files"] == [
        "rollback_target.txt"
    ]
    transaction_updates = [
        json.loads(line)
        for line in change_applier.CHANGE_TRANSACTIONS_FILE.read_text(
            encoding="utf-8"
        ).splitlines()
    ]
    assert {
        update["transaction_id"]
        for update in transaction_updates
    } == {transaction_id}
    assert [update["state"] for update in transaction_updates] == [
        "PROPOSED",
        "AWAITING_PERMISSION",
        "APPROVED",
        "APPLYING",
        "VALIDATING",
        "SUCCEEDED",
    ]


@pytest.mark.parametrize(
    ("approved_files", "expected_scope_status"),
    [
        (["../outside.py"], "FAILED"),
        (
            ["rollback_target.txt", "not_modified.py"],
            "INCONCLUSIVE",
        ),
    ],
)
def test_scope_validation_failure_or_inconclusive_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    approved_files: list[str],
    expected_scope_status: change_applier.ScopeStatus,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": approved_files,
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }

    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="diagnosis-run-id",
        previous_failure_file=approved_files[0],
    )

    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    assert change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    ) is False
    assert target_path.read_text(encoding="utf-8") == original_content

    validation_record = json.loads(
        (project_dir / "logs" / "validation_results.jsonl").read_text(
            encoding="utf-8",
        ).strip()
    )
    assert validation_record["change_aware_validation_status"] == "PASSED"
    assert validation_record["scope_validation_status"] == expected_scope_status
    assert validation_record["final_validation_status"] == expected_scope_status
    transaction_record = change_transaction.get_transaction(
        transaction_id,
        change_applier.CHANGE_TRANSACTIONS_FILE,
    )
    assert transaction_record is not None
    assert transaction_record["state"] == "ROLLED_BACK"
    assert transaction_record["final_outcome"] == "ROLLED_BACK"
    assert transaction_record["rollback_succeeded"] is True


def test_apply_change_rolls_back_when_validation_record_cannot_be_persisted(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }

    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="diagnosis-run-id",
    )
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    invalid_parent = tmp_path / "not-a-directory"
    invalid_parent.write_text("file blocks log directory", encoding="utf-8")
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        invalid_parent / "validation_results.jsonl",
    )

    assert change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    ) is False
    assert target_path.read_text(encoding="utf-8") == original_content


def test_mismatched_transaction_id_rejects_change_before_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    permission["transaction_id"] = "different-transaction-id"
    monkeypatch.setattr(change_applier, "PROJECT_FOLDER", project_dir)

    assert (
        change_applier.apply_change(
            diagnosis,
            permission,
            transaction_id,
        )
        is False
    )
    assert target_path.read_text(encoding="utf-8") == original_content
    transaction = change_transaction.get_transaction(
        transaction_id,
        change_applier.CHANGE_TRANSACTIONS_FILE,
    )
    assert transaction is not None
    assert transaction["state"] == "APPROVED"


def test_untracked_transaction_id_cannot_authorize_change(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    diagnosis["transaction_id"] = "untracked-transaction"
    permission["transaction_id"] = "untracked-transaction"
    monkeypatch.setattr(change_applier, "PROJECT_FOLDER", project_dir)

    assert change_applier.can_apply_change(diagnosis, permission) is True
    assert change_applier.apply_change(
        diagnosis,
        permission,
        "untracked-transaction",
    ) is False
    assert target_path.read_text(encoding="utf-8") == original_content
    transaction = change_transaction.get_transaction(
        transaction_id,
        change_applier.CHANGE_TRANSACTIONS_FILE,
    )
    assert transaction is not None
    assert transaction["state"] == "APPROVED"


def test_failed_rollback_records_failed_transaction(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Test diagnosis",
            "likely_cause": "Test cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }
    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    monkeypatch.setattr(change_applier, "PROJECT_FOLDER", project_dir)
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        tmp_path / "logs" / "validation_results.jsonl",
    )
    monkeypatch.setattr(
        change_applier,
        "analyze_post_change_validation",
        lambda run_id, _files: {
            "previous_run_id": run_id,
            "post_change_run_id": "post-change-run",
            "post_change_test_status": "FAILED",
            "change_aware_validation_status": "FAILED",
            "validation_evidence": ["Post-change validation failed."],
        },
    )
    monkeypatch.setattr(
        change_applier,
        "restore_original_file",
        lambda _target, _content: False,
    )

    assert change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    ) is False
    transaction = change_transaction.get_transaction(
        transaction_id,
        change_applier.CHANGE_TRANSACTIONS_FILE,
    )
    assert transaction is not None
    assert transaction["state"] == "FAILED"
    assert transaction["final_outcome"] == "FAILED"
    assert transaction["rollback_succeeded"] is False


def test_transaction_persistence_failure_rolls_back_successful_validation(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")
    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }
    permission = make_approved_permission(diagnosis)
    transaction_log = tmp_path / "logs" / "change_transactions.jsonl"
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
        transaction_log,
    )
    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="diagnosis-run-id",
    )
    monkeypatch.setattr(change_applier, "PROJECT_FOLDER", project_dir)

    append_transaction = change_transaction._append_transaction

    def fail_success_event(
        record: change_transaction.ChangeTransaction,
        log_path: Path,
    ) -> None:
        if record["state"] == "SUCCEEDED":
            append_transaction(record, log_path)
            raise OSError("simulated transaction log failure")
        append_transaction(record, log_path)

    monkeypatch.setattr(
        change_transaction,
        "_append_transaction",
        fail_success_event,
    )

    assert change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    ) is False
    assert target_path.read_text(encoding="utf-8") == original_content
    transaction = change_transaction.get_transaction(
        transaction_id,
        transaction_log,
    )
    assert transaction is not None
    assert transaction["state"] == "ROLLED_BACK"
    assert transaction["final_outcome"] == "ROLLED_BACK"
    assert transaction["final_validation_status"] == "PASSED"


def test_apply_change_rolls_back_when_real_validation_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }

    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=1,
        previous_run_id="diagnosis-run-id",
    )

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )

    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    success = change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    )

    assert success is False
    assert target_path.read_text(encoding="utf-8") == original_content


def test_apply_change_rolls_back_when_real_validation_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_dir = tmp_path / "project"
    project_dir.mkdir(parents=True, exist_ok=True)
    target_path = project_dir / "rollback_target.txt"
    original_content = "original value\n"
    target_path.write_text(original_content, encoding="utf-8")

    diagnosis: change_applier.DiagnosisRecord = {
        "run_id": "diagnosis-run-id",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Integration diagnosis",
            "likely_cause": "Integration cause",
            "file": "rollback_target.txt",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Apply the change",
            "proposed_change": "Use new content",
            "affected_files": ["rollback_target.txt"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "rollback_target.txt",
                "line": 1,
                "old_text": original_content,
                "new_text": "changed value\n",
            },
        },
    }
    permission: change_applier.PermissionRecord = {
        "run_id": "diagnosis-run-id",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "rollback_target.txt",
        "line": 1,
        "proposed_change": "Use new content",
        "affected_files": ["rollback_target.txt"],
        "change_size": "SMALL",
        "exact_change": {
            "file": "rollback_target.txt",
            "line": 1,
            "old_text": original_content,
            "new_text": "changed value\n",
        },
    }

    _prepare_real_tester_environment(
        monkeypatch=monkeypatch,
        tmp_path=tmp_path,
        exit_code=0,
        previous_run_id="diagnosis-run-id",
        previous_failure_file="unrelated_test.py",
    )
    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_dir,
    )

    permission = make_approved_permission(diagnosis)
    transaction_id = prepare_approved_transaction(
        monkeypatch,
        tmp_path,
        diagnosis,
        permission,
    )
    assert change_applier.can_apply_change(diagnosis, permission) is True
    assert change_applier.apply_change(
        diagnosis,
        permission,
        transaction_id,
    ) is False
    assert target_path.read_text(encoding="utf-8") == original_content
    assert "Change-aware validation status: INCONCLUSIVE" in capsys.readouterr().out