from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, NotRequired, TypedDict, cast

from change_transaction import (
    InvalidTransactionTransition,
    TransactionLogError,
    get_transaction,
    transition_transaction,
)


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

DIAGNOSES_FILE = LOG_FOLDER / "diagnoses.jsonl"
PERMISSIONS_FILE = LOG_FOLDER / "permissions.jsonl"
CHANGE_TRANSACTIONS_FILE = LOG_FOLDER / "change_transactions.jsonl"


ChangeSize = Literal[
    "NONE",
    "SMALL",
    "MEDIUM",
    "LARGE",
]


Decision = Literal[
    "APPROVED",
    "REJECTED",
]


class ExactChange(TypedDict):
    file: str | None
    line: int | None
    old_text: str | None
    new_text: str | None


class DiagnosisData(TypedDict):
    status: str
    diagnosis: str
    likely_cause: str
    file: str | None
    line: int | None
    confidence: str
    evidence: list[str]
    next_step: str
    proposed_change: str
    affected_files: list[str]
    change_size: ChangeSize
    exact_change: ExactChange


class DiagnosisRecord(TypedDict):
    run_id: str
    timestamp: str
    test_timestamp: str
    test_status: str
    diagnosis: DiagnosisData
    transaction_id: NotRequired[str | None]


class PermissionRecord(TypedDict):
    run_id: str
    diagnosis_timestamp: str
    permission_timestamp: str
    decision: Decision
    file: str | None
    line: int | None
    proposed_change: str
    affected_files: list[str]
    change_size: ChangeSize
    exact_change: ExactChange
    transaction_id: NotRequired[str | None]


def load_latest_diagnosis() -> DiagnosisRecord | None:
    if not DIAGNOSES_FILE.exists():
        return None

    latest_diagnosis: DiagnosisRecord | None = None

    with DIAGNOSES_FILE.open(
        "r",
        encoding="utf-8",
    ) as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                value: object = json.loads(line)
            except json.JSONDecodeError:
                continue

            if not isinstance(value, dict):
                continue

            value_object = cast(
                dict[object, object],
                value,
            )

            record = parse_diagnosis(
                value_object
            )

            if record is not None:
                latest_diagnosis = record

    return latest_diagnosis


def parse_diagnosis(
    value: dict[object, object],
) -> DiagnosisRecord | None:
    run_id = value.get(
        "run_id"
    )

    timestamp = value.get(
        "timestamp"
    )

    test_timestamp = value.get(
        "test_timestamp"
    )

    test_status = value.get(
        "test_status"
    )

    transaction_id = value.get("transaction_id")

    diagnosis_value = value.get(
        "diagnosis"
    )

    if not isinstance(
        run_id,
        str,
    ):
        return None

    if not run_id:
        return None

    if not isinstance(
        timestamp,
        str,
    ):
        return None

    if not isinstance(
        test_timestamp,
        str,
    ):
        return None

    if not isinstance(
        test_status,
        str,
    ):
        return None

    if transaction_id is not None and (
        not isinstance(transaction_id, str) or not transaction_id
    ):
        return None

    if not isinstance(
        diagnosis_value,
        dict,
    ):
        return None

    diagnosis_object = cast(
        dict[object, object],
        diagnosis_value,
    )

    diagnosis = parse_diagnosis_data(
        diagnosis_object
    )

    if diagnosis is None:
        return None

    record: DiagnosisRecord = {
        "run_id": run_id,
        "timestamp": timestamp,
        "test_timestamp": test_timestamp,
        "test_status": test_status,
        "diagnosis": diagnosis,
    }
    if isinstance(transaction_id, str):
        record["transaction_id"] = transaction_id
    return record


def parse_exact_change(
    value: object,
) -> ExactChange | None:
    if not isinstance(
        value,
        dict,
    ):
        return None

    change_object = cast(
        dict[object, object],
        value,
    )

    file = change_object.get(
        "file"
    )

    line = change_object.get(
        "line"
    )

    old_text = change_object.get(
        "old_text"
    )

    new_text = change_object.get(
        "new_text"
    )

    if file is not None and not isinstance(
        file,
        str,
    ):
        return None

    if line is not None and not isinstance(
        line,
        int,
    ):
        return None

    if old_text is not None and not isinstance(
        old_text,
        str,
    ):
        return None

    if new_text is not None and not isinstance(
        new_text,
        str,
    ):
        return None

    return {
        "file": file,
        "line": line,
        "old_text": old_text,
        "new_text": new_text,
    }


def parse_diagnosis_data(
    value: dict[object, object],
) -> DiagnosisData | None:
    status = value.get(
        "status"
    )

    diagnosis = value.get(
        "diagnosis"
    )

    likely_cause = value.get(
        "likely_cause"
    )

    file = value.get(
        "file"
    )

    line = value.get(
        "line"
    )

    confidence = value.get(
        "confidence"
    )

    evidence = value.get(
        "evidence"
    )

    next_step = value.get(
        "next_step"
    )

    proposed_change = value.get(
        "proposed_change"
    )

    affected_files = value.get(
        "affected_files"
    )

    change_size = value.get(
        "change_size"
    )

    exact_change = parse_exact_change(
        value.get(
            "exact_change"
        )
    )

    if not isinstance(
        status,
        str,
    ):
        return None

    if not isinstance(
        diagnosis,
        str,
    ):
        return None

    if not isinstance(
        likely_cause,
        str,
    ):
        return None

    if file is not None and not isinstance(
        file,
        str,
    ):
        return None

    if line is not None and not isinstance(
        line,
        int,
    ):
        return None

    if not isinstance(
        confidence,
        str,
    ):
        return None

    if not isinstance(
        evidence,
        list,
    ):
        return None

    evidence_strings: list[str] = []

    evidence_values = cast(
        list[object],
        evidence,
    )

    for item in evidence_values:
        if not isinstance(
            item,
            str,
        ):
            return None

        evidence_strings.append(
            item
        )

    if not isinstance(
        next_step,
        str,
    ):
        return None

    if not isinstance(
        proposed_change,
        str,
    ):
        return None

    if not isinstance(
        affected_files,
        list,
    ):
        return None

    affected_file_strings: list[str] = []

    affected_file_values = cast(
        list[object],
        affected_files,
    )

    for item in affected_file_values:
        if not isinstance(
            item,
            str,
        ):
            return None

        affected_file_strings.append(
            item
        )

    if change_size not in {
        "NONE",
        "SMALL",
        "MEDIUM",
        "LARGE",
    }:
        return None

    if exact_change is None:
        return None

    typed_change_size = cast(
        ChangeSize,
        change_size,
    )

    return {
        "status": status,
        "diagnosis": diagnosis,
        "likely_cause": likely_cause,
        "file": file,
        "line": line,
        "confidence": confidence,
        "evidence": evidence_strings,
        "next_step": next_step,
        "proposed_change": proposed_change,
        "affected_files": affected_file_strings,
        "change_size": typed_change_size,
        "exact_change": exact_change,
    }


def save_permission(
    diagnosis: DiagnosisRecord,
    decision: Decision,
    transaction_id: str | None = None,
) -> PermissionRecord:
    diagnosis_data = diagnosis[
        "diagnosis"
    ]

    permission_timestamp = datetime.now(
        timezone.utc
    ).isoformat(
        timespec="milliseconds"
    )

    record: PermissionRecord = {
        "run_id": diagnosis[
            "run_id"
        ],
        "diagnosis_timestamp": diagnosis[
            "timestamp"
        ],
        "permission_timestamp": permission_timestamp,
        "decision": decision,
        "file": diagnosis_data[
            "file"
        ],
        "line": diagnosis_data[
            "line"
        ],
        "proposed_change": diagnosis_data[
            "proposed_change"
        ],
        "affected_files": diagnosis_data[
            "affected_files"
        ],
        "change_size": diagnosis_data[
            "change_size"
        ],
        "exact_change": diagnosis_data[
            "exact_change"
        ],
    }
    if transaction_id is not None:
        record["transaction_id"] = transaction_id

    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    with PERMISSIONS_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:
        json.dump(
            record,
            file,
            ensure_ascii=False,
        )

        file.write("\n")

    return record


def print_change_request(
    diagnosis: DiagnosisRecord,
) -> None:
    diagnosis_data = diagnosis[
        "diagnosis"
    ]

    exact_change = diagnosis_data[
        "exact_change"
    ]

    print()
    print("=" * 50)
    print("CHANGE PERMISSION")
    print("=" * 50)

    print()

    print("Diagnosis:")
    print(
        diagnosis_data[
            "diagnosis"
        ]
    )

    print()

    print("Proposed change:")
    print(
        diagnosis_data[
            "proposed_change"
        ]
    )

    print()

    print("Exact change:")

    print(
        f"File: "
        f"{exact_change['file'] or 'Unknown'}"
    )

    print(
        f"Line: "
        f"{exact_change['line'] or 'Unknown'}"
    )

    print()

    print("Old:")
    print(
        exact_change[
            "old_text"
        ]
        or "Unknown"
    )

    print()

    print("New:")
    print(
        exact_change[
            "new_text"
        ]
        or "Unknown"
    )

    print()

    print("Affected files:")

    affected_files = diagnosis_data[
        "affected_files"
    ]

    if affected_files:
        for file_path in affected_files:
            print(
                f"  {file_path}"
            )
    else:
        print(
            "  None"
        )

    print()

    print("Change size:")
    print(
        diagnosis_data[
            "change_size"
        ]
    )

    print()
    print("=" * 50)


def ask_permission() -> Decision:
    while True:
        answer = input(
            "Allow this change? [y/N]: "
        ).strip().lower()

        if answer in {
            "y",
            "yes",
        }:
            return "APPROVED"

        if answer in {
            "",
            "n",
            "no",
        }:
            return "REJECTED"

        print(
            "Please enter y or n."
        )


def main(transaction_id: str | None = None) -> int:
    diagnosis = load_latest_diagnosis()

    if diagnosis is None:
        print(
            "No valid diagnosis found."
        )
        return 1

    if transaction_id is not None:
        try:
            transaction = get_transaction(
                transaction_id,
                CHANGE_TRANSACTIONS_FILE,
            )
        except TransactionLogError as error:
            print(f"Transaction audit log could not be read: {error}")
            return 1
        if (
            diagnosis.get("transaction_id") != transaction_id
            or transaction is None
            or transaction["state"] != "PROPOSED"
            or transaction["diagnosis_run_id"] != diagnosis["run_id"]
            or transaction["pre_change_run_id"] != diagnosis["run_id"]
        ):
            print("Transaction ID does not match this diagnosis lifecycle.")
            return 1

        try:
            transition_transaction(
                transaction_id,
                "PROPOSED",
                "AWAITING_PERMISSION",
                {
                    "diagnosis_timestamp": diagnosis["timestamp"],
                    "evidence": ["Awaiting the user's permission decision."],
                },
                CHANGE_TRANSACTIONS_FILE,
            )
        except (
            InvalidTransactionTransition,
            OSError,
            TransactionLogError,
        ) as error:
            print(f"Transaction audit update failed: {error}")
            return 1

    diagnosis_data = diagnosis[
        "diagnosis"
    ]

    if diagnosis_data[
        "change_size"
    ] == "NONE":
        print(
            "No change has been proposed."
        )
        if transaction_id is not None:
            try:
                transition_transaction(
                    transaction_id,
                    "AWAITING_PERMISSION",
                    "INCONCLUSIVE",
                    {
                        "evidence": [
                            "Diagnosis did not propose an exact change."
                        ],
                    },
                    CHANGE_TRANSACTIONS_FILE,
                )
            except (
                InvalidTransactionTransition,
                OSError,
                TransactionLogError,
            ) as error:
                print(f"Transaction audit update failed: {error}")
                return 1
        return 0

    print_change_request(
        diagnosis
    )

    decision = ask_permission()

    try:
        permission = save_permission(
            diagnosis,
            decision,
            transaction_id,
        )
        if transaction_id is not None:
            new_state = (
                "APPROVED"
                if decision == "APPROVED"
                else "REJECTED"
            )
            transition_transaction(
                transaction_id,
                "AWAITING_PERMISSION",
                new_state,
                {
                    "permission_timestamp": permission[
                        "permission_timestamp"
                    ],
                    "permission_decision": decision,
                    "affected_files": permission["affected_files"],
                    "evidence": [
                        f"Permission decision recorded: {decision}."
                    ],
                },
                CHANGE_TRANSACTIONS_FILE,
            )
    except (
        InvalidTransactionTransition,
        OSError,
        TransactionLogError,
    ) as error:
        print(f"Permission or transaction record could not be saved: {error}")
        return 1

    print()

    if decision == "APPROVED":
        print(
            "Permission granted."
        )
        print(
            "No files have been modified."
        )
    else:
        print(
            "Change rejected."
        )
        print(
            "No files have been modified."
        )

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--transaction-id")
    raise SystemExit(main(parser.parse_args().transaction_id))