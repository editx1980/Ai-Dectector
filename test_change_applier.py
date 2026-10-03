import json
import subprocess
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


def _prepare_real_tester_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    exit_code: int,
    previous_run_id: str,
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

    config_path = project_dir / "overseer.json"
    config_path.write_text(
        json.dumps(
            {
                "test_command": [
                    "python",
                    "-c",
                    command_script,
                ]
            }
        ),
        encoding="utf-8",
    )

    test_result_path = logs_dir / "test_results.jsonl"
    test_result_path.write_text(
        json.dumps(
            {
                "run_id": previous_run_id,
                "status": "PASSED",
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
            "old-run-id"
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
            "old-run-id"
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
                "status": "PASSED",
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
            "old-run-id"
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
                "status": "PASSED",
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
            "old-run-id"
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

    success = change_applier.apply_change(diagnosis)

    assert success is True
    assert target_path.read_text(encoding="utf-8") == "changed value\n"
    assert change_applier.can_apply_change(diagnosis, permission) is True


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

    success = change_applier.apply_change(diagnosis)

    assert success is False
    assert target_path.read_text(encoding="utf-8") == original_content