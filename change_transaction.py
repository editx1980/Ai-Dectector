from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict, cast

from change_risk_analyzer import (
    ChangeRiskAssessment,
    parse_change_risk_assessment,
)


TransactionState = Literal[
    "PROPOSED",
    "AWAITING_PERMISSION",
    "APPROVED",
    "REJECTED",
    "APPLYING",
    "VALIDATING",
    "SUCCEEDED",
    "ROLLED_BACK",
    "INCONCLUSIVE",
    "FAILED",
]

TransactionOutcome = Literal[
    "SUCCESS",
    "ROLLED_BACK",
    "FAILED",
    "INCONCLUSIVE",
    "REJECTED",
]

TransactionStatus = Literal[
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
]

PermissionDecision = Literal[
    "APPROVED",
    "REJECTED",
]


class ChangeTransaction(TypedDict):
    transaction_id: str
    created_at: str
    updated_at: str
    state: TransactionState
    diagnosis_run_id: str
    pre_change_run_id: str
    post_change_run_id: str | None
    diagnosis_timestamp: str | None
    permission_timestamp: str | None
    permission_decision: PermissionDecision | None
    risk_assessment: ChangeRiskAssessment | None
    affected_files: list[str]
    actual_changed_files: list[str]
    post_change_test_status: TransactionStatus | None
    change_aware_validation_status: TransactionStatus | None
    scope_validation_status: TransactionStatus | None
    final_validation_status: TransactionStatus | None
    rollback_succeeded: bool | None
    final_outcome: TransactionOutcome | None
    evidence: list[str]


class TransactionUpdate(TypedDict, total=False):
    diagnosis_timestamp: str | None
    permission_timestamp: str | None
    permission_decision: PermissionDecision | None
    risk_assessment: ChangeRiskAssessment
    affected_files: list[str]
    actual_changed_files: list[str]
    post_change_run_id: str | None
    post_change_test_status: TransactionStatus | None
    change_aware_validation_status: TransactionStatus | None
    scope_validation_status: TransactionStatus | None
    final_validation_status: TransactionStatus | None
    rollback_succeeded: bool | None
    final_outcome: TransactionOutcome | None
    evidence: list[str]


class TransactionLogError(ValueError):
    pass


class InvalidTransactionTransition(ValueError):
    pass


_ALLOWED_TRANSITIONS: dict[
    TransactionState,
    frozenset[TransactionState],
] = {
    "PROPOSED": frozenset(
        {"AWAITING_PERMISSION", "FAILED", "INCONCLUSIVE"}
    ),
    "AWAITING_PERMISSION": frozenset(
        {"APPROVED", "REJECTED", "INCONCLUSIVE", "FAILED"}
    ),
    "APPROVED": frozenset({"APPLYING", "FAILED"}),
    "REJECTED": frozenset(),
    "APPLYING": frozenset(
        {"VALIDATING", "ROLLED_BACK", "FAILED"}
    ),
    "VALIDATING": frozenset(
        {"SUCCEEDED", "ROLLED_BACK", "FAILED"}
    ),
    "SUCCEEDED": frozenset({"ROLLED_BACK", "FAILED"}),
    "ROLLED_BACK": frozenset(),
    "INCONCLUSIVE": frozenset(),
    "FAILED": frozenset(),
}


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(
        timespec="microseconds"
    )


def _is_status(value: object) -> bool:
    return isinstance(value, str) and value in {
        "PASSED",
        "FAILED",
        "INCONCLUSIVE",
    }


def _parse_transaction(value: object, line_number: int) -> ChangeTransaction:
    if not isinstance(value, dict):
        raise TransactionLogError(
            f"Transaction log line {line_number} is not a JSON object."
        )

    record = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in record):
        raise TransactionLogError(
            f"Transaction log line {line_number} has a non-string key."
        )

    transaction_id = record.get("transaction_id")
    created_at = record.get("created_at")
    updated_at = record.get("updated_at")
    state = record.get("state")
    diagnosis_run_id = record.get("diagnosis_run_id")
    pre_change_run_id = record.get("pre_change_run_id")
    post_change_run_id = record.get("post_change_run_id")
    diagnosis_timestamp = record.get("diagnosis_timestamp")
    permission_timestamp = record.get("permission_timestamp")
    permission_decision = record.get("permission_decision")
    raw_risk_assessment = record.get("risk_assessment")
    affected_files = record.get("affected_files")
    actual_changed_files = record.get("actual_changed_files")
    post_change_test_status = record.get("post_change_test_status")
    change_aware_validation_status = record.get(
        "change_aware_validation_status"
    )
    scope_validation_status = record.get("scope_validation_status")
    final_validation_status = record.get("final_validation_status")
    rollback_succeeded = record.get("rollback_succeeded")
    final_outcome = record.get("final_outcome")
    evidence = record.get("evidence")

    states = {
        "PROPOSED",
        "AWAITING_PERMISSION",
        "APPROVED",
        "REJECTED",
        "APPLYING",
        "VALIDATING",
        "SUCCEEDED",
        "ROLLED_BACK",
        "INCONCLUSIVE",
        "FAILED",
    }
    outcomes = {
        "SUCCESS",
        "ROLLED_BACK",
        "FAILED",
        "INCONCLUSIVE",
        "REJECTED",
    }
    decisions = {"APPROVED", "REJECTED"}

    if not isinstance(transaction_id, str) or not transaction_id:
        raise TransactionLogError(
            f"Transaction log line {line_number} has no transaction ID."
        )
    if not isinstance(created_at, str) or not isinstance(updated_at, str):
        raise TransactionLogError(
            f"Transaction log line {line_number} has invalid timestamps."
        )
    if not isinstance(state, str) or state not in states:
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid state."
        )
    if not isinstance(diagnosis_run_id, str) or not diagnosis_run_id:
        raise TransactionLogError(
            f"Transaction log line {line_number} has no diagnosis run ID."
        )
    if not isinstance(pre_change_run_id, str) or not pre_change_run_id:
        raise TransactionLogError(
            f"Transaction log line {line_number} has no pre-change run ID."
        )
    if post_change_run_id is not None and not isinstance(
        post_change_run_id, str
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid post-change run ID."
        )
    if diagnosis_timestamp is not None and not isinstance(
        diagnosis_timestamp, str
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid diagnosis timestamp."
        )
    if permission_timestamp is not None and not isinstance(
        permission_timestamp, str
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid permission timestamp."
        )
    if permission_decision is not None and (
        not isinstance(permission_decision, str)
        or permission_decision not in decisions
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid permission decision."
        )
    risk_assessment = (
        parse_change_risk_assessment(raw_risk_assessment)
        if raw_risk_assessment is not None
        else None
    )
    if raw_risk_assessment is not None and risk_assessment is None:
        raise TransactionLogError(
            f"Transaction log line {line_number} has invalid risk assessment."
        )
    if (
        risk_assessment is not None
        and risk_assessment["originating_run_id"] != diagnosis_run_id
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} links risk to another run ID."
        )
    if not isinstance(affected_files, list) or not all(
        isinstance(path, str) for path in cast(list[object], affected_files)
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has invalid approved files."
        )
    if not isinstance(actual_changed_files, list) or not all(
        isinstance(path, str)
        for path in cast(list[object], actual_changed_files)
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has invalid actual files."
        )
    if any(
        status is not None and not _is_status(status)
        for status in (
            post_change_test_status,
            change_aware_validation_status,
            scope_validation_status,
            final_validation_status,
        )
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid validation status."
        )
    if rollback_succeeded is not None and not isinstance(
        rollback_succeeded, bool
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid rollback status."
        )
    if final_outcome is not None and (
        not isinstance(final_outcome, str) or final_outcome not in outcomes
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has an invalid final outcome."
        )
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) for item in cast(list[object], evidence)
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} has invalid evidence."
        )

    parsed: ChangeTransaction = {
        "transaction_id": transaction_id,
        "created_at": created_at,
        "updated_at": updated_at,
        "state": cast(TransactionState, state),
        "diagnosis_run_id": diagnosis_run_id,
        "pre_change_run_id": pre_change_run_id,
        "post_change_run_id": post_change_run_id,
        "diagnosis_timestamp": diagnosis_timestamp,
        "permission_timestamp": permission_timestamp,
        "permission_decision": cast(
            PermissionDecision | None, permission_decision
        ),
        "risk_assessment": risk_assessment,
        "affected_files": cast(list[str], affected_files),
        "actual_changed_files": cast(list[str], actual_changed_files),
        "post_change_test_status": cast(
            TransactionStatus | None, post_change_test_status
        ),
        "change_aware_validation_status": cast(
            TransactionStatus | None, change_aware_validation_status
        ),
        "scope_validation_status": cast(
            TransactionStatus | None, scope_validation_status
        ),
        "final_validation_status": cast(
            TransactionStatus | None, final_validation_status
        ),
        "rollback_succeeded": rollback_succeeded,
        "final_outcome": cast(TransactionOutcome | None, final_outcome),
        "evidence": cast(list[str], evidence),
    }
    _validate_final_record(parsed, line_number)
    return parsed


def _validate_final_record(
    transaction: ChangeTransaction,
    line_number: int,
) -> None:
    state = transaction["state"]
    outcome = transaction["final_outcome"]

    if state == "SUCCEEDED" and not (
        outcome == "SUCCESS"
        and transaction["post_change_test_status"] == "PASSED"
        and transaction["change_aware_validation_status"] == "PASSED"
        and transaction["scope_validation_status"] == "PASSED"
        and transaction["final_validation_status"] == "PASSED"
        and transaction["rollback_succeeded"] is False
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} records unsafe success."
        )
    if state == "REJECTED" and not (
        outcome == "REJECTED"
        and transaction["permission_decision"] == "REJECTED"
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} records an invalid rejection."
        )
    if state == "ROLLED_BACK" and not (
        outcome == "ROLLED_BACK"
        and transaction["rollback_succeeded"] is True
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} records an invalid rollback."
        )
    if state == "FAILED" and outcome != "FAILED":
        raise TransactionLogError(
            f"Transaction log line {line_number} records an invalid failure."
        )
    if state == "INCONCLUSIVE" and not (
        outcome == "INCONCLUSIVE"
        and not transaction["actual_changed_files"]
        and transaction["rollback_succeeded"] is None
    ):
        raise TransactionLogError(
            f"Transaction log line {line_number} records an invalid inconclusive outcome."
        )


def load_latest_transactions(
    log_path: Path,
) -> dict[str, ChangeTransaction]:
    if not log_path.exists():
        return {}

    latest: dict[str, ChangeTransaction] = {}
    try:
        with log_path.open("r", encoding="utf-8") as file:
            for line_number, line in enumerate(file, start=1):
                if not line.strip():
                    continue
                try:
                    raw: object = json.loads(line)
                except json.JSONDecodeError as error:
                    raise TransactionLogError(
                        f"Transaction log line {line_number} is invalid JSON."
                    ) from error
                transaction = _parse_transaction(raw, line_number)
                previous = latest.get(transaction["transaction_id"])
                if previous is not None:
                    risk_was_added_at_permission = (
                        previous["risk_assessment"] is None
                        and transaction["risk_assessment"] is not None
                        and previous["state"] == "PROPOSED"
                        and transaction["state"] == "AWAITING_PERMISSION"
                    )
                    risk_changed = (
                        previous["risk_assessment"]
                        != transaction["risk_assessment"]
                    )
                    if (
                        transaction["created_at"] != previous["created_at"]
                        or transaction["diagnosis_run_id"]
                        != previous["diagnosis_run_id"]
                        or transaction["pre_change_run_id"]
                        != previous["pre_change_run_id"]
                        or (risk_changed and not risk_was_added_at_permission)
                        or transaction["state"]
                        not in _ALLOWED_TRANSITIONS[previous["state"]]
                    ):
                        raise TransactionLogError(
                            "Transaction log contains an invalid update for "
                            f"{transaction['transaction_id']}."
                        )
                elif transaction["state"] != "PROPOSED":
                    raise TransactionLogError(
                        "A transaction log must begin in PROPOSED state."
                    )
                latest[transaction["transaction_id"]] = transaction
    except OSError as error:
        raise TransactionLogError(
            f"Could not read transaction log: {error}"
        ) from error

    return latest


def get_transaction(
    transaction_id: str,
    log_path: Path,
) -> ChangeTransaction | None:
    return load_latest_transactions(log_path).get(transaction_id)


def _append_transaction(
    transaction: ChangeTransaction,
    log_path: Path,
) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8") as file:
        file.write(
            json.dumps(transaction, ensure_ascii=False) + "\n"
        )


def create_transaction(
    diagnosis_run_id: str,
    pre_change_run_id: str,
    log_path: Path,
) -> ChangeTransaction:
    if not diagnosis_run_id or not pre_change_run_id:
        raise ValueError("Diagnosis and pre-change run IDs are required.")

    transaction_id = str(uuid.uuid4())
    existing = load_latest_transactions(log_path)
    if transaction_id in existing:
        raise TransactionLogError(
            "Generated transaction ID already exists in the audit log."
        )

    now = _timestamp()
    transaction: ChangeTransaction = {
        "transaction_id": transaction_id,
        "created_at": now,
        "updated_at": now,
        "state": "PROPOSED",
        "diagnosis_run_id": diagnosis_run_id,
        "pre_change_run_id": pre_change_run_id,
        "post_change_run_id": None,
        "diagnosis_timestamp": None,
        "permission_timestamp": None,
        "permission_decision": None,
        "risk_assessment": None,
        "affected_files": [],
        "actual_changed_files": [],
        "post_change_test_status": None,
        "change_aware_validation_status": None,
        "scope_validation_status": None,
        "final_validation_status": None,
        "rollback_succeeded": None,
        "final_outcome": None,
        "evidence": [],
    }
    _append_transaction(transaction, log_path)
    return transaction


def transition_transaction(
    transaction_id: str,
    expected_state: TransactionState,
    new_state: TransactionState,
    updates: TransactionUpdate,
    log_path: Path,
) -> ChangeTransaction:
    transaction = get_transaction(transaction_id, log_path)
    if transaction is None:
        raise TransactionLogError(
            f"Transaction {transaction_id} is not present in the audit log."
        )
    if transaction["state"] != expected_state:
        raise InvalidTransactionTransition(
            f"Expected transaction state {expected_state}, found "
            f"{transaction['state']}."
        )
    if new_state not in _ALLOWED_TRANSITIONS[expected_state]:
        raise InvalidTransactionTransition(
            f"Transaction cannot transition from {expected_state} to {new_state}."
        )

    updated: ChangeTransaction = {
        **transaction,
        "updated_at": _timestamp(),
        "state": new_state,
        "evidence": [
            *transaction["evidence"],
            *updates.get("evidence", []),
        ],
    }
    if "diagnosis_timestamp" in updates:
        updated["diagnosis_timestamp"] = updates["diagnosis_timestamp"]
    if "permission_timestamp" in updates:
        updated["permission_timestamp"] = updates["permission_timestamp"]
    if "permission_decision" in updates:
        updated["permission_decision"] = updates["permission_decision"]
    if "risk_assessment" in updates:
        if not (
            expected_state == "PROPOSED"
            and new_state == "AWAITING_PERMISSION"
            and transaction["risk_assessment"] is None
            and updates["risk_assessment"]["originating_run_id"]
            == transaction["diagnosis_run_id"]
        ):
            raise InvalidTransactionTransition(
                "Risk assessment may only be recorded once when entering "
                "AWAITING_PERMISSION for the diagnosis run."
            )
        updated["risk_assessment"] = updates["risk_assessment"]
    if "affected_files" in updates:
        updated["affected_files"] = updates["affected_files"]
    if "actual_changed_files" in updates:
        updated["actual_changed_files"] = updates["actual_changed_files"]
    if "post_change_run_id" in updates:
        updated["post_change_run_id"] = updates["post_change_run_id"]
    if "post_change_test_status" in updates:
        updated["post_change_test_status"] = updates[
            "post_change_test_status"
        ]
    if "change_aware_validation_status" in updates:
        updated["change_aware_validation_status"] = updates[
            "change_aware_validation_status"
        ]
    if "scope_validation_status" in updates:
        updated["scope_validation_status"] = updates[
            "scope_validation_status"
        ]
    if "final_validation_status" in updates:
        updated["final_validation_status"] = updates[
            "final_validation_status"
        ]
    if "rollback_succeeded" in updates:
        updated["rollback_succeeded"] = updates["rollback_succeeded"]
    if "final_outcome" in updates:
        updated["final_outcome"] = updates["final_outcome"]

    if new_state == "REJECTED":
        if updated["permission_decision"] != "REJECTED":
            raise InvalidTransactionTransition(
                "A rejected transaction must record a rejected permission."
            )
        updated["final_outcome"] = "REJECTED"
    elif new_state == "SUCCEEDED":
        if not (
            updated["post_change_test_status"] == "PASSED"
            and updated["change_aware_validation_status"] == "PASSED"
            and updated["scope_validation_status"] == "PASSED"
            and updated["final_validation_status"] == "PASSED"
            and updated["rollback_succeeded"] is False
        ):
            raise InvalidTransactionTransition(
                "A transaction cannot succeed unless every validation passes."
            )
        updated["final_outcome"] = "SUCCESS"
    elif new_state == "ROLLED_BACK":
        if updated["rollback_succeeded"] is not True:
            raise InvalidTransactionTransition(
                "A rolled-back transaction must confirm successful rollback."
            )
        updated["final_outcome"] = "ROLLED_BACK"
    elif new_state == "INCONCLUSIVE":
        if updated["actual_changed_files"] or updated["rollback_succeeded"] is not None:
            raise InvalidTransactionTransition(
                "An inconclusive outcome is only valid before any change is recorded."
            )
        updated["final_outcome"] = "INCONCLUSIVE"
    elif new_state == "FAILED":
        updated["final_outcome"] = "FAILED"

    _append_transaction(updated, log_path)
    return updated
