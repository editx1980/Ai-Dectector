import json
import tempfile
from pathlib import Path

import permission_manager


def main() -> None:
    with tempfile.TemporaryDirectory() as folder:
        temp_folder = Path(folder)
        permission_file = (
            temp_folder / "permissions.jsonl"
        )

        original_log_folder = (
            permission_manager.LOG_FOLDER
        )
        original_permission_file = (
            permission_manager.PERMISSIONS_FILE
        )

        permission_manager.LOG_FOLDER = (
            temp_folder
        )
        permission_manager.PERMISSIONS_FILE = (
            permission_file
        )

        diagnosis: permission_manager.DiagnosisRecord = {
            "run_id": "test-run-123",
            "timestamp": (
                "2026-10-01T17:00:00.000+00:00"
            ),
            "test_timestamp": (
                "2026-10-01T16:59:00.000+00:00"
            ),
            "test_status": "FAILED",
            "diagnosis": {
                "status": "FAILED",
                "diagnosis": "Test diagnosis.",
                "likely_cause": "Test cause.",
                "file": "test_failure.py",
                "line": 5,
                "confidence": "HIGH",
                "evidence": [
                    "Test evidence.",
                ],
                "next_step": (
                    "Apply the proposed change."
                ),
                "proposed_change": (
                    "Change the test value."
                ),
                "affected_files": [
                    "test_failure.py",
                ],
                "change_size": "SMALL",
                "exact_change": {
                    "file": "test_failure.py",
                    "line": 5,
                    "old_text": "old",
                    "new_text": "new",
                },
            },
        }

        try:
            permission_manager.save_permission(
                diagnosis,
                "APPROVED",
            )

            records = (
                permission_file.read_text(
                    encoding="utf-8"
                )
                .strip()
                .splitlines()
            )

            assert len(records) == 1

            record = json.loads(
                records[0]
            )

            assert (
                record["run_id"]
                == "test-run-123"
            )

            assert (
                record["diagnosis_timestamp"]
                == "2026-10-01T17:00:00.000+00:00"
            )

            assert record[
                "permission_timestamp"
            ]

            assert (
                record[
                    "permission_timestamp"
                ]
                != record[
                    "diagnosis_timestamp"
                ]
            )

            assert (
                record["decision"]
                == "APPROVED"
            )

            assert (
                record["exact_change"][
                    "old_text"
                ]
                == "old"
            )

            assert (
                record["exact_change"][
                    "new_text"
                ]
                == "new"
            )

            print(
                "Change 5 permission test passed."
            )

        finally:
            permission_manager.LOG_FOLDER = (
                original_log_folder
            )
            permission_manager.PERMISSIONS_FILE = (
                original_permission_file
            )


if __name__ == "__main__":
    main()