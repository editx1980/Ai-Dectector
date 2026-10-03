from pathlib import Path

import pytest

import change_transaction


def create_transaction(
    log_path: Path,
) -> change_transaction.ChangeTransaction:
    return change_transaction.create_transaction(
        diagnosis_run_id="diagnosis-run-123",
        pre_change_run_id="pre-change-run-123",
        log_path=log_path,
    )


def test_transaction_creation_has_unique_id_and_proposed_state(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "logs" / "change_transactions.jsonl"

    first = create_transaction(log_path)
    second = create_transaction(log_path)

    assert first["transaction_id"] != second["transaction_id"]
    assert first["transaction_id"] != first["diagnosis_run_id"]
    assert first["diagnosis_run_id"] == "diagnosis-run-123"
    assert first["pre_change_run_id"] == "pre-change-run-123"
    assert first["state"] == "PROPOSED"
    assert first["created_at"] == first["updated_at"]


def test_valid_transitions_append_snapshots_and_load_latest_state(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)

    awaiting = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "AWAITING_PERMISSION",
        {"diagnosis_timestamp": "diagnosis-time"},
        log_path,
    )
    approved = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "AWAITING_PERMISSION",
        "APPROVED",
        {
            "permission_timestamp": "permission-time",
            "permission_decision": "APPROVED",
            "affected_files": ["src/module.py"],
        },
        log_path,
    )

    assert awaiting["updated_at"] != ""
    assert approved["state"] == "APPROVED"
    assert approved["transaction_id"] == transaction["transaction_id"]
    assert approved["diagnosis_run_id"] == "diagnosis-run-123"
    assert approved["pre_change_run_id"] == "pre-change-run-123"
    assert len(log_path.read_text(encoding="utf-8").splitlines()) == 3
    assert (
        change_transaction.get_transaction(
            transaction["transaction_id"],
            log_path,
        )
        == approved
    )


def test_invalid_transition_is_rejected_without_appending(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)
    before = log_path.read_text(encoding="utf-8")

    with pytest.raises(
        change_transaction.InvalidTransactionTransition
    ):
        change_transaction.transition_transaction(
            transaction["transaction_id"],
            "PROPOSED",
            "SUCCEEDED",
            {},
            log_path,
        )

    assert log_path.read_text(encoding="utf-8") == before


def test_rejected_permission_is_a_terminal_rejected_outcome(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "AWAITING_PERMISSION",
        {},
        log_path,
    )

    rejected = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "AWAITING_PERMISSION",
        "REJECTED",
        {
            "permission_timestamp": "permission-time",
            "permission_decision": "REJECTED",
        },
        log_path,
    )

    assert rejected["state"] == "REJECTED"
    assert rejected["final_outcome"] == "REJECTED"


def test_success_requires_every_validation_stage_to_pass(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "AWAITING_PERMISSION",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "AWAITING_PERMISSION",
        "APPROVED",
        {"permission_decision": "APPROVED"},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPROVED",
        "APPLYING",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPLYING",
        "VALIDATING",
        {},
        log_path,
    )

    with pytest.raises(
        change_transaction.InvalidTransactionTransition
    ):
        change_transaction.transition_transaction(
            transaction["transaction_id"],
            "VALIDATING",
            "SUCCEEDED",
            {
                "post_change_test_status": "PASSED",
                "change_aware_validation_status": "PASSED",
                "scope_validation_status": "INCONCLUSIVE",
                "final_validation_status": "INCONCLUSIVE",
                "rollback_succeeded": False,
            },
            log_path,
        )

    succeeded = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "VALIDATING",
        "SUCCEEDED",
        {
            "post_change_run_id": "post-change-run-123",
            "post_change_test_status": "PASSED",
            "change_aware_validation_status": "PASSED",
            "scope_validation_status": "PASSED",
            "final_validation_status": "PASSED",
            "rollback_succeeded": False,
        },
        log_path,
    )
    assert succeeded["final_outcome"] == "SUCCESS"
    assert succeeded["post_change_run_id"] == "post-change-run-123"


@pytest.mark.parametrize(
    ("state", "updates", "expected_outcome"),
    [
        (
            "ROLLED_BACK",
            {"rollback_succeeded": True},
            "ROLLED_BACK",
        ),
        (
            "FAILED",
            {"rollback_succeeded": False},
            "FAILED",
        ),
    ],
)
def test_terminal_non_success_outcomes_are_recorded(
    tmp_path: Path,
    state: change_transaction.TransactionState,
    updates: change_transaction.TransactionUpdate,
    expected_outcome: change_transaction.TransactionOutcome,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "AWAITING_PERMISSION",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "AWAITING_PERMISSION",
        "APPROVED",
        {"permission_decision": "APPROVED"},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPROVED",
        "APPLYING",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPLYING",
        "VALIDATING",
        {},
        log_path,
    )

    result = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "VALIDATING",
        state,
        updates,
        log_path,
    )
    assert result["final_outcome"] == expected_outcome


def test_inconclusive_outcome_is_only_available_before_a_change(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)

    inconclusive = change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "INCONCLUSIVE",
        {"evidence": ["No diagnosis could be established."]},
        log_path,
    )

    assert inconclusive["final_outcome"] == "INCONCLUSIVE"


def test_success_cannot_be_recorded_without_rollback_status(
    tmp_path: Path,
) -> None:
    log_path = tmp_path / "change_transactions.jsonl"
    transaction = create_transaction(log_path)
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "PROPOSED",
        "AWAITING_PERMISSION",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "AWAITING_PERMISSION",
        "APPROVED",
        {"permission_decision": "APPROVED"},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPROVED",
        "APPLYING",
        {},
        log_path,
    )
    change_transaction.transition_transaction(
        transaction["transaction_id"],
        "APPLYING",
        "VALIDATING",
        {},
        log_path,
    )

    with pytest.raises(
        change_transaction.InvalidTransactionTransition
    ):
        change_transaction.transition_transaction(
            transaction["transaction_id"],
            "VALIDATING",
            "SUCCEEDED",
            {
                "post_change_test_status": "PASSED",
                "change_aware_validation_status": "PASSED",
                "scope_validation_status": "PASSED",
                "final_validation_status": "PASSED",
            },
            log_path,
        )
