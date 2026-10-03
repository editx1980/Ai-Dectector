from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import ai_diagnoser
import change_applier
import change_transaction
import permission_manager
from validation_analyzer import parse_test_result


SOURCE_ROOT = Path(__file__).resolve().parent


def test_applier_permission_parser_supports_transaction_and_legacy_records() -> None:
    record: dict[object, object] = {
        "run_id": "originating-run",
        "diagnosis_timestamp": "diagnosis-time",
        "permission_timestamp": "permission-time",
        "decision": "APPROVED",
        "file": "src/module.py",
        "line": 3,
        "proposed_change": "Update the value.",
        "affected_files": ["src/module.py"],
        "change_size": "SMALL",
        "exact_change": {
            "file": "src/module.py",
            "line": 3,
            "old_text": "old",
            "new_text": "new",
        },
        "transaction_id": "stable-transaction-id",
    }

    parsed = change_applier.parse_permission(record)
    assert parsed is not None
    assert parsed["transaction_id"] == "stable-transaction-id"

    record.pop("transaction_id")
    legacy = change_applier.parse_permission(record)
    assert legacy is not None
    assert legacy.get("transaction_id") is None


def run_real_tester(project_root: Path) -> dict[str, object]:
    result = subprocess.run(
        [sys.executable, str(project_root / "tester.py")],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    records = [
        json.loads(line)
        for line in (project_root / "logs" / "test_results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert records
    return records[-1]


def test_diagnosis_risk_permission_apply_and_real_validation_chain(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project_root = tmp_path / "project"
    log_folder = project_root / "logs"
    log_folder.mkdir(parents=True)
    shutil.copy2(SOURCE_ROOT / "tester.py", project_root / "tester.py")
    shutil.copy2(
        SOURCE_ROOT / "runtime_monitor.py",
        project_root / "runtime_monitor.py",
    )
    test_file = project_root / "test_target.py"
    test_file.write_text(
        "def test_target_value():\n"
        "    value = 'old'\n"
        "    assert value == 'new'\n",
        encoding="utf-8",
    )
    (project_root / "overseer.json").write_text(
        json.dumps(
            {
                "test_command": [
                    sys.executable,
                    "-m",
                    "pytest",
                    "-v",
                    "test_target.py",
                ]
            }
        ),
        encoding="utf-8",
    )

    test_results_file = log_folder / "test_results.jsonl"
    pre_change_raw = run_real_tester(project_root)
    pre_change_result = parse_test_result(pre_change_raw)
    assert pre_change_result is not None
    assert pre_change_result["status"] == "FAILED"
    assert pre_change_result["failures"]
    run_id = pre_change_result["run_id"]

    transaction_file = log_folder / "change_transactions.jsonl"
    transaction = change_transaction.create_transaction(
        run_id,
        run_id,
        transaction_file,
    )
    transaction_id = transaction["transaction_id"]

    monkeypatch.setattr(ai_diagnoser, "LOG_FOLDER", log_folder)
    monkeypatch.setattr(
        ai_diagnoser,
        "DIAGNOSES_FILE",
        log_folder / "diagnoses.jsonl",
    )
    monkeypatch.setattr(
        ai_diagnoser,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_file,
    )
    diagnosis = ai_diagnoser.Diagnosis(
        status="FAILED",
        diagnosis="The tested value differs from the expected value.",
        likely_cause="The value is still set to the old value.",
        file="test_target.py",
        line=2,
        confidence="HIGH",
        evidence=["The originating pytest run recorded the assertion failure."],
        next_step="Change the value to the expected value.",
        proposed_change="Set the tested value to 'new'.",
        affected_files=["test_target.py"],
        change_size="SMALL",
        exact_change={
            "file": "test_target.py",
            "line": 2,
            "old_text": "value = 'old'",
            "new_text": "value = 'new'",
        },
    )
    ai_diagnoser.write_diagnosis(
        {
            "run_id": run_id,
            "timestamp": "pre-change-test-timestamp",
            "test": {"status": "FAILED"},
        },
        diagnosis,
        transaction_id,
    )

    monkeypatch.setattr(
        permission_manager,
        "DIAGNOSES_FILE",
        log_folder / "diagnoses.jsonl",
    )
    monkeypatch.setattr(
        permission_manager,
        "PERMISSIONS_FILE",
        log_folder / "permissions.jsonl",
    )
    monkeypatch.setattr(permission_manager, "LOG_FOLDER", log_folder)
    monkeypatch.setattr(
        permission_manager,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_file,
    )
    monkeypatch.setattr(
        permission_manager,
        "TEST_RESULTS_FILE",
        test_results_file,
    )
    monkeypatch.setattr(
        permission_manager,
        "ask_permission",
        lambda: "APPROVED",
    )

    assert permission_manager.main(transaction_id) == 0
    permission_output = capsys.readouterr().out
    for required_context in (
        transaction_id,
        run_id,
        "The tested value differs from the expected value.",
        "The value is still set to the old value.",
        "Set the tested value to 'new'.",
        "Risk: MEDIUM",
        "Diagnosis-provided proposed scope",
        "Originating test context",
        "Exact edit being approved",
        "Explicit user permission is still required.",
    ):
        assert required_context in permission_output
    permission_record = json.loads(
        (log_folder / "permissions.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()[-1]
    )
    assert permission_record["run_id"] == run_id
    assert permission_record["transaction_id"] == transaction_id
    assert permission_record["risk_assessment"]["originating_run_id"] == run_id
    assert permission_record["risk_assessment"]["test_status"] == "FAILED"
    assert permission_record["risk_assessment"]["level"] == "MEDIUM"

    monkeypatch.setattr(
        change_applier,
        "PROJECT_FOLDER",
        project_root,
    )
    monkeypatch.setattr(
        change_applier,
        "DIAGNOSES_FILE",
        log_folder / "diagnoses.jsonl",
    )
    monkeypatch.setattr(
        change_applier,
        "PERMISSIONS_FILE",
        log_folder / "permissions.jsonl",
    )
    monkeypatch.setattr(
        change_applier,
        "TEST_RESULTS_FILE",
        test_results_file,
    )
    monkeypatch.setattr(
        change_applier,
        "VALIDATION_RESULTS_FILE",
        log_folder / "validation_results.jsonl",
    )
    monkeypatch.setattr(
        change_applier,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_file,
    )
    monkeypatch.setattr(
        change_applier,
        "TESTER_FILE",
        project_root / "tester.py",
    )

    assert change_applier.main(transaction_id) == 0
    assert "value = 'new'" in test_file.read_text(encoding="utf-8")

    final_transaction = change_transaction.get_transaction(
        transaction_id,
        transaction_file,
    )
    assert final_transaction is not None
    assert final_transaction["state"] == "SUCCEEDED"
    assert final_transaction["final_outcome"] == "SUCCESS"
    assert final_transaction["diagnosis_run_id"] == run_id
    assert final_transaction["pre_change_run_id"] == run_id
    assert final_transaction["post_change_run_id"] != run_id
    assert final_transaction["post_change_test_status"] == "PASSED"
    assert final_transaction["change_aware_validation_status"] == "PASSED"
    assert final_transaction["scope_validation_status"] == "PASSED"
    assert final_transaction["risk_assessment"] is not None
    assert final_transaction["risk_assessment"]["originating_run_id"] == run_id

    validation_records = [
        json.loads(line)
        for line in (log_folder / "validation_results.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
        if line.strip()
    ]
    assert len(validation_records) == 1
    assert validation_records[0]["transaction_id"] == transaction_id
    assert validation_records[0]["final_validation_status"] == "PASSED"
