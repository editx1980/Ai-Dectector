import json
from pathlib import Path

import pytest

import ai_diagnoser
import change_transaction
import permission_manager


def test_diagnosis_persists_explicit_transaction_link(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    diagnosis_path = tmp_path / "diagnoses.jsonl"
    transaction = change_transaction.create_transaction(
        "failed-test-run",
        "failed-test-run",
        log_path,
    )
    monkeypatch.setattr(ai_diagnoser, "CHANGE_TRANSACTIONS_FILE", log_path)
    monkeypatch.setattr(ai_diagnoser, "DIAGNOSES_FILE", diagnosis_path)
    monkeypatch.setattr(ai_diagnoser, "LOG_FOLDER", tmp_path)

    diagnosis = ai_diagnoser.Diagnosis(
        status="FAILED",
        diagnosis="The failing assertion uses the old value.",
        likely_cause="The value is stale.",
        file="src/module.py",
        line=12,
        confidence="HIGH",
        evidence=["A failed test run identified this location."],
        next_step="Replace the stale value.",
        proposed_change="Use the expected value.",
        affected_files=["src/module.py"],
        change_size="SMALL",
        exact_change={
            "file": "src/module.py",
            "line": 12,
            "old_text": "old",
            "new_text": "new",
        },
    )
    evidence: ai_diagnoser.JsonObject = {
        "run_id": "failed-test-run",
        "timestamp": "test-run-timestamp",
        "test": {"status": "FAILED"},
    }

    ai_diagnoser.write_diagnosis(
        evidence,
        diagnosis,
        transaction["transaction_id"],
    )

    diagnosis_record = json.loads(
        diagnosis_path.read_text(encoding="utf-8").strip()
    )
    assert diagnosis_record["transaction_id"] == transaction["transaction_id"]
    assert diagnosis_record["run_id"] == "failed-test-run"


def test_permission_approval_and_rejection_persist_transaction_states(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    diagnosis_path = tmp_path / "diagnoses.jsonl"
    permission_path = tmp_path / "permissions.jsonl"
    transaction_path = tmp_path / "change_transactions.jsonl"
    monkeypatch.setattr(permission_manager, "DIAGNOSES_FILE", diagnosis_path)
    monkeypatch.setattr(permission_manager, "PERMISSIONS_FILE", permission_path)
    monkeypatch.setattr(permission_manager, "LOG_FOLDER", tmp_path)
    monkeypatch.setattr(
        permission_manager,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_path,
    )

    for decision in ("APPROVED", "REJECTED"):
        transaction = change_transaction.create_transaction(
            f"run-{decision.lower()}",
            f"run-{decision.lower()}",
            transaction_path,
        )
        transaction_id = transaction["transaction_id"]
        diagnosis_record = {
            "run_id": f"run-{decision.lower()}",
            "timestamp": f"diagnosis-{decision.lower()}",
            "test_timestamp": "pre-test-time",
            "test_status": "FAILED",
            "transaction_id": transaction_id,
            "diagnosis": {
                "status": "FAILED",
                "diagnosis": "The failure is caused by an old value.",
                "likely_cause": "Stale value.",
                "file": "src/module.py",
                "line": 12,
                "confidence": "HIGH",
                "evidence": ["A failing test."],
                "next_step": "Update the value.",
                "proposed_change": "Use the expected value.",
                "affected_files": ["src/module.py"],
                "change_size": "SMALL",
                "exact_change": {
                    "file": "src/module.py",
                    "line": 12,
                    "old_text": "old",
                    "new_text": "new",
                },
            },
        }
        diagnosis_path.write_text(
            json.dumps(diagnosis_record) + "\n",
            encoding="utf-8",
        )
        monkeypatch.setattr(
            permission_manager,
            "ask_permission",
            lambda: decision,
        )

        assert permission_manager.main(transaction_id) == 0

        permission_record = json.loads(
            permission_path.read_text(encoding="utf-8").splitlines()[-1]
        )
        assert permission_record["transaction_id"] == transaction_id
        assert permission_record["decision"] == decision
        current = change_transaction.get_transaction(
            transaction_id,
            transaction_path,
        )
        assert current is not None
        assert current["state"] == decision
        assert current["permission_decision"] == decision
        assert current["permission_timestamp"] == permission_record[
            "permission_timestamp"
        ]


def test_legacy_diagnosis_without_transaction_id_remains_parseable() -> None:
    diagnosis = permission_manager.parse_diagnosis(
        {
            "run_id": "legacy-run",
            "timestamp": "diagnosis-time",
            "test_timestamp": "test-time",
            "test_status": "FAILED",
            "diagnosis": {
                "status": "FAILED",
                "diagnosis": "Legacy diagnosis.",
                "likely_cause": "Legacy cause.",
                "file": "legacy.py",
                "line": 1,
                "confidence": "HIGH",
                "evidence": [],
                "next_step": "Update.",
                "proposed_change": "Change.",
                "affected_files": ["legacy.py"],
                "change_size": "SMALL",
                "exact_change": {
                    "file": "legacy.py",
                    "line": 1,
                    "old_text": "old",
                    "new_text": "new",
                },
            },
        }
    )

    assert diagnosis is not None
    assert diagnosis.get("transaction_id") is None


def test_wrong_transaction_id_cannot_advance_permission_stage(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transaction_path = tmp_path / "change_transactions.jsonl"
    transaction = change_transaction.create_transaction(
        "matching-run",
        "matching-run",
        transaction_path,
    )
    diagnosis = {
        "run_id": "matching-run",
        "timestamp": "diagnosis-time",
        "test_timestamp": "test-time",
        "test_status": "FAILED",
        "transaction_id": "different-transaction",
        "diagnosis": {
            "status": "FAILED",
            "diagnosis": "Diagnosis.",
            "likely_cause": "Cause.",
            "file": "src/module.py",
            "line": 1,
            "confidence": "HIGH",
            "evidence": [],
            "next_step": "Update.",
            "proposed_change": "Change.",
            "affected_files": ["src/module.py"],
            "change_size": "SMALL",
            "exact_change": {
                "file": "src/module.py",
                "line": 1,
                "old_text": "old",
                "new_text": "new",
            },
        },
    }
    monkeypatch.setattr(
        permission_manager,
        "load_latest_diagnosis",
        lambda: diagnosis,
    )
    monkeypatch.setattr(
        permission_manager,
        "CHANGE_TRANSACTIONS_FILE",
        transaction_path,
    )

    assert permission_manager.main(transaction["transaction_id"]) == 1
    current = change_transaction.get_transaction(
        transaction["transaction_id"],
        transaction_path,
    )
    assert current is not None
    assert current["state"] == "PROPOSED"
