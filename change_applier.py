from __future__ import annotations

import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal, TypedDict, cast

from runtime_monitor import COMMAND_TIMEOUT_SECONDS
from scope_analyzer import (
    ScopeStatus,
    ScopeValidationResult,
    compare_scopes,
)
from validation_analyzer import (
    TestResult,
    ValidationStatus,
    ValidationComparison,
    compare_test_results,
    parse_test_result,
)


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

DIAGNOSES_FILE = LOG_FOLDER / "diagnoses.jsonl"
PERMISSIONS_FILE = LOG_FOLDER / "permissions.jsonl"
TEST_RESULTS_FILE = LOG_FOLDER / "test_results.jsonl"
VALIDATION_RESULTS_FILE = LOG_FOLDER / "validation_results.jsonl"
TESTER_FILE = PROJECT_FOLDER / "tester.py"


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
    change_size: str
    exact_change: ExactChange


class DiagnosisRecord(TypedDict):
    run_id: str
    timestamp: str
    test_timestamp: str
    test_status: str
    diagnosis: DiagnosisData


class PermissionRecord(TypedDict):
    run_id: str
    diagnosis_timestamp: str
    permission_timestamp: str
    decision: Decision
    file: str | None
    line: int | None
    proposed_change: str
    affected_files: list[str]
    change_size: str
    exact_change: ExactChange


class PostChangeValidationResult(TypedDict):
    previous_run_id: str
    post_change_run_id: str | None
    change_aware_validation_status: ValidationStatus
    validation_evidence: list[str]


class UnifiedValidationRecord(TypedDict):
    transaction_id: str
    diagnosis_timestamp: str
    permission_timestamp: str
    timestamp: str
    previous_run_id: str
    post_change_run_id: str | None
    change_file: str
    expected_files: list[str]
    actual_files: list[str] | None
    unexpected_files: list[str]
    missing_expected_files: list[str]
    change_aware_validation_status: ValidationStatus
    scope_validation_status: ScopeStatus
    final_validation_status: ValidationStatus
    scope_evidence: list[str]
    validation_evidence: list[str]


def load_latest_diagnosis() -> DiagnosisRecord | None:
    if not DIAGNOSES_FILE.exists():
        return None

    latest: DiagnosisRecord | None = None

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

            record = parse_diagnosis(
                cast(
                    dict[object, object],
                    value,
                )
            )

            if record is not None:
                latest = record

    return latest


def parse_exact_change(
    value: object,
) -> ExactChange | None:
    if not isinstance(
        value,
        dict,
    ):
        return None

    change = cast(
        dict[object, object],
        value,
    )

    file = change.get("file")
    line = change.get("line")
    old_text = change.get("old_text")
    new_text = change.get("new_text")

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


def parse_diagnosis(
    value: dict[object, object],
) -> DiagnosisRecord | None:
    run_id = value.get("run_id")
    timestamp = value.get("timestamp")
    test_timestamp = value.get("test_timestamp")
    test_status = value.get("test_status")
    diagnosis_value = value.get("diagnosis")

    if not isinstance(run_id, str) or not run_id:
        return None

    if not isinstance(timestamp, str):
        return None

    if not isinstance(test_timestamp, str):
        return None

    if not isinstance(test_status, str):
        return None

    if not isinstance(diagnosis_value, dict):
        return None

    diagnosis = parse_diagnosis_data(
        cast(
            dict[object, object],
            diagnosis_value,
        )
    )

    if diagnosis is None:
        return None

    return {
        "run_id": run_id,
        "timestamp": timestamp,
        "test_timestamp": test_timestamp,
        "test_status": test_status,
        "diagnosis": diagnosis,
    }


def parse_diagnosis_data(
    value: dict[object, object],
) -> DiagnosisData | None:
    status = value.get("status")
    diagnosis = value.get("diagnosis")
    likely_cause = value.get("likely_cause")
    file = value.get("file")
    line = value.get("line")
    confidence = value.get("confidence")
    evidence = value.get("evidence")
    next_step = value.get("next_step")
    proposed_change = value.get("proposed_change")
    affected_files = value.get("affected_files")
    change_size = value.get("change_size")
    exact_change = parse_exact_change(
        value.get("exact_change")
    )

    if not isinstance(status, str):
        return None

    if not isinstance(diagnosis, str):
        return None

    if not isinstance(likely_cause, str):
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

    if not isinstance(confidence, str):
        return None

    if not isinstance(evidence, list):
        return None

    evidence_values = cast(
        list[object],
        evidence,
    )

    evidence_strings: list[str] = []

    for item in evidence_values:
        if not isinstance(item, str):
            return None

        evidence_strings.append(item)

    if not isinstance(next_step, str):
        return None

    if not isinstance(proposed_change, str):
        return None

    if not isinstance(affected_files, list):
        return None

    affected_file_values = cast(
        list[object],
        affected_files,
    )

    affected_file_strings: list[str] = []

    for item in affected_file_values:
        if not isinstance(item, str):
            return None

        affected_file_strings.append(item)

    if not isinstance(change_size, str):
        return None

    if exact_change is None:
        return None

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
        "change_size": change_size,
        "exact_change": exact_change,
    }


def load_latest_permission() -> PermissionRecord | None:
    if not PERMISSIONS_FILE.exists():
        return None

    latest: PermissionRecord | None = None

    with PERMISSIONS_FILE.open(
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

            record = parse_permission(
                cast(
                    dict[object, object],
                    value,
                )
            )

            if record is not None:
                latest = record

    return latest


def parse_permission(
    value: dict[object, object],
) -> PermissionRecord | None:
    run_id = value.get("run_id")
    diagnosis_timestamp = value.get(
        "diagnosis_timestamp"
    )
    permission_timestamp = value.get(
        "permission_timestamp"
    )
    decision = value.get("decision")
    file = value.get("file")
    line = value.get("line")
    proposed_change = value.get("proposed_change")
    affected_files = value.get("affected_files")
    change_size = value.get("change_size")
    exact_change = parse_exact_change(
        value.get("exact_change")
    )

    if not isinstance(run_id, str) or not run_id:
        return None

    if not isinstance(
        diagnosis_timestamp,
        str,
    ):
        return None

    if not isinstance(
        permission_timestamp,
        str,
    ):
        return None

    if decision not in {
        "APPROVED",
        "REJECTED",
    }:
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
        proposed_change,
        str,
    ):
        return None

    if not isinstance(
        affected_files,
        list,
    ):
        return None

    affected_file_values = cast(
        list[object],
        affected_files,
    )

    affected_file_strings: list[str] = []

    for item in affected_file_values:
        if not isinstance(item, str):
            return None

        affected_file_strings.append(item)

    if not isinstance(
        change_size,
        str,
    ):
        return None

    if exact_change is None:
        return None

    return {
        "run_id": run_id,
        "diagnosis_timestamp": diagnosis_timestamp,
        "permission_timestamp": permission_timestamp,
        "decision": cast(
            Decision,
            decision,
        ),
        "file": file,
        "line": line,
        "proposed_change": proposed_change,
        "affected_files": affected_file_strings,
        "change_size": change_size,
        "exact_change": exact_change,
    }


def permission_matches_diagnosis(
    diagnosis: DiagnosisRecord,
    permission: PermissionRecord,
) -> bool:
    diagnosis_data = diagnosis["diagnosis"]

    if permission["decision"] != "APPROVED":
        return False

    if permission["run_id"] != diagnosis["run_id"]:
        return False

    if (
        permission["diagnosis_timestamp"]
        != diagnosis["timestamp"]
    ):
        return False

    if permission["file"] != diagnosis_data["file"]:
        return False

    if permission["line"] != diagnosis_data["line"]:
        return False

    if (
        permission["proposed_change"]
        != diagnosis_data["proposed_change"]
    ):
        return False

    if (
        permission["affected_files"]
        != diagnosis_data["affected_files"]
    ):
        return False

    if (
        permission["change_size"]
        != diagnosis_data["change_size"]
    ):
        return False

    if (
        permission["exact_change"]
        != diagnosis_data["exact_change"]
    ):
        return False

    return True


def can_apply_change(
    diagnosis: DiagnosisRecord,
    permission: PermissionRecord | None,
) -> bool:
    if permission is None:
        return False

    return permission_matches_diagnosis(
        diagnosis,
        permission,
    )


def resolve_target_file(
    file_path: str,
) -> Path | None:
    target = (
        PROJECT_FOLDER / file_path
    ).resolve()

    try:
        target.relative_to(
            PROJECT_FOLDER.resolve()
        )
    except ValueError:
        return None

    return target


def apply_exact_change(
    diagnosis: DiagnosisRecord,
) -> tuple[bool, Path | None, str | None]:
    exact_change = diagnosis[
        "diagnosis"
    ]["exact_change"]

    file_path = exact_change["file"]
    old_text = exact_change["old_text"]
    new_text = exact_change["new_text"]

    if file_path is None:
        print(
            "Change cannot be applied."
        )
        print(
            "The exact change does not contain a file."
        )
        return False, None, None

    if old_text is None:
        print(
            "Change cannot be applied."
        )
        print(
            "The exact change does not contain old text."
        )
        return False, None, None

    if new_text is None:
        print(
            "Change cannot be applied."
        )
        print(
            "The exact change does not contain new text."
        )
        return False, None, None

    target = resolve_target_file(
        file_path
    )

    if target is None:
        print(
            "Change cannot be applied."
        )
        print(
            "The target file is outside the project."
        )
        return False, None, None

    if not target.exists():
        print(
            "Change cannot be applied."
        )
        print(
            f"File does not exist: {file_path}"
        )
        return False, None, None

    try:
        current_content = target.read_text(
            encoding="utf-8"
        )
    except (
        OSError,
        UnicodeDecodeError,
    ) as error:
        print(
            "Change cannot be applied."
        )
        print(
            f"Could not read file: {error}"
        )
        return False, None, None

    occurrence_count = current_content.count(
        old_text
    )

    if occurrence_count == 0:
        print(
            "Change cannot be applied."
        )
        print(
            "The expected old text was not found."
        )
        print(
            "The file may have changed since diagnosis."
        )
        return False, None, None

    if occurrence_count != 1:
        print(
            "Change cannot be applied."
        )
        print(
            "The expected old text occurs "
            f"{occurrence_count} times."
        )
        print(
            "The change is ambiguous."
        )
        return False, None, None

    updated_content = current_content.replace(
        old_text,
        new_text,
        1,
    )

    try:
        target.write_text(
            updated_content,
            encoding="utf-8",
        )
    except OSError as error:
        print(
            "Change could not be written."
        )
        print(
            f"Write error: {error}"
        )
        return False, None, None

    print()
    print("Change applied.")
    print(
        f"File: {file_path}"
    )

    return True, target, current_content


def restore_original_file(
    target: Path,
    original_content: str,
) -> bool:
    try:
        target.write_text(
            original_content,
            encoding="utf-8",
        )
    except OSError as error:
        print()
        print(
            "CRITICAL: Rollback failed."
        )
        print(
            f"Could not restore {target}: {error}"
        )
        return False

    return True


def get_latest_test_result() -> dict[object, object] | None:
    if not TEST_RESULTS_FILE.exists():
        return None

    latest: dict[object, object] | None = None

    with TEST_RESULTS_FILE.open(
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

            latest = cast(
                dict[object, object],
                value,
            )

    return latest


def load_test_results() -> list[TestResult]:
    if not TEST_RESULTS_FILE.exists():
        return []

    results: list[TestResult] = []

    try:
        with TEST_RESULTS_FILE.open(
            "r",
            encoding="utf-8",
        ) as file:
            for line in file:
                stripped_line = line.strip()

                if not stripped_line:
                    continue

                try:
                    value: object = json.loads(stripped_line)
                except json.JSONDecodeError:
                    continue

                result = parse_test_result(value)

                if result is not None:
                    results.append(result)
    except OSError as error:
        print()
        print("Test results could not be read.")
        print(f"Result log error: {error}")

    return results


def analyze_post_change_validation(
    expected_previous_run_id: str,
    affected_files: list[str],
) -> PostChangeValidationResult:
    previous_results = load_test_results()
    previous_result = next(
        (
            test_result
            for test_result in previous_results
            if test_result["run_id"] == expected_previous_run_id
        ),
        None,
    )
    existing_run_ids = {
        test_result["run_id"]
        for test_result in previous_results
    }

    if not TESTER_FILE.exists():
        print()
        print(
            "Post-change validation could not run."
        )
        print(
            "tester.py was not found."
        )
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                "tester.py was not found."
            ],
        }

    try:
        result = subprocess.run(
            [
                sys.executable,
                str(TESTER_FILE),
            ],
            cwd=PROJECT_FOLDER,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        print()
        print(
            "Post-change validation failed."
        )
        print(
            "tester.py exceeded the configured timeout."
        )
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                "tester.py exceeded the configured timeout."
            ],
        }
    except OSError as error:
        print()
        print(
            "Post-change validation could not run."
        )
        print(
            f"Validation error: {error}"
        )
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                f"Could not execute tester.py: {error}"
            ],
        }

    if result.returncode != 0:
        print()
        print(
            "Post-change validation failed."
        )
        print(
            f"tester.py exited with code "
            f"{result.returncode}."
        )
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                f"tester.py exited with code {result.returncode}."
            ],
        }

    try:
        current_result = get_latest_test_result()
    except OSError as error:
        print()
        print(
            "Post-change validation could not be confirmed."
        )
        print(f"Test result log could not be read: {error}")
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "INCONCLUSIVE",
            "validation_evidence": [
                f"Test result log could not be read: {error}"
            ],
        }

    if current_result is None:
        print()
        print(
            "Post-change validation could not be confirmed."
        )
        print(
            "No test result was recorded."
        )
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "INCONCLUSIVE",
            "validation_evidence": [
                "No post-change test result was recorded."
            ],
        }

    post_change_result = parse_test_result(current_result)

    if post_change_result is None:
        print()
        print(
            "Post-change validation could not be confirmed."
        )
        print("The latest test result is missing required data.")
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": None,
            "change_aware_validation_status": "INCONCLUSIVE",
            "validation_evidence": [
                "The latest test result is missing required data."
            ],
        }

    if post_change_result["run_id"] == expected_previous_run_id:
        print()
        print(
            "Post-change validation could not be confirmed."
        )
        print("The test run ID did not change.")
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": post_change_result["run_id"],
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                "The test run ID did not change."
            ],
        }

    if post_change_result["run_id"] in existing_run_ids:
        print()
        print(
            "Post-change validation could not be confirmed."
        )
        print("The latest result was already present before validation.")
        return {
            "previous_run_id": expected_previous_run_id,
            "post_change_run_id": post_change_result["run_id"],
            "change_aware_validation_status": "FAILED",
            "validation_evidence": [
                "The latest result was already present before validation."
            ],
        }

    comparison: ValidationComparison = compare_test_results(
        previous_result,
        post_change_result,
        affected_files,
    )

    print()
    print(
        "Change-aware validation status: "
        f"{comparison['validation_status']}"
    )

    for evidence_item in comparison["evidence"]:
        print(f"- {evidence_item}")

    return {
        "previous_run_id": expected_previous_run_id,
        "post_change_run_id": post_change_result["run_id"],
        "change_aware_validation_status": comparison[
            "validation_status"
        ],
        "validation_evidence": comparison["evidence"],
    }


def run_post_change_validation(
    expected_previous_run_id: str,
    affected_files: list[str] | None = None,
) -> bool:
    result = analyze_post_change_validation(
        expected_previous_run_id,
        affected_files or [],
    )

    return result["change_aware_validation_status"] == "PASSED"


def combine_validation_statuses(
    change_aware_status: ValidationStatus,
    scope_status: ScopeStatus,
) -> ValidationStatus:
    if (
        change_aware_status == "FAILED"
        or scope_status == "FAILED"
    ):
        return "FAILED"

    if (
        change_aware_status == "INCONCLUSIVE"
        or scope_status == "INCONCLUSIVE"
    ):
        return "INCONCLUSIVE"

    return "PASSED"


def write_validation_result(
    record: UnifiedValidationRecord,
) -> bool:
    try:
        VALIDATION_RESULTS_FILE.parent.mkdir(
            parents=True,
            exist_ok=True,
        )
        with VALIDATION_RESULTS_FILE.open(
            "a",
            encoding="utf-8",
        ) as file:
            file.write(
                json.dumps(
                    record,
                    ensure_ascii=False,
                )
                + "\n"
            )
    except OSError as error:
        print()
        print("Validation result could not be persisted.")
        print(f"Validation log error: {error}")
        return False

    return True


def apply_change(
    diagnosis: DiagnosisRecord,
    permission: PermissionRecord,
) -> bool:
    if not can_apply_change(
        diagnosis,
        permission,
    ):
        print("No matching approved permission found.")
        print("No files have been modified.")
        return False

    transaction_id = str(uuid.uuid4())
    expected_files = permission["affected_files"]

    applied, target, original_content = (
        apply_exact_change(
            diagnosis
        )
    )

    if not applied:
        print()
        print(
            "No files have been modified."
        )
        return False

    if target is None or original_content is None:
        print()
        print(
            "Change cannot be safely validated."
        )
        return False

    actual_files = [str(target)]
    post_change_validation = analyze_post_change_validation(
        diagnosis["run_id"],
        expected_files,
    )
    scope_validation: ScopeValidationResult = compare_scopes(
        expected_files,
        actual_files,
        PROJECT_FOLDER,
    )
    final_status = combine_validation_statuses(
        post_change_validation["change_aware_validation_status"],
        scope_validation["scope_status"],
    )

    print()
    print(
        f"Scope validation status: "
        f"{scope_validation['scope_status']}"
    )
    for evidence_item in scope_validation["evidence"]:
        print(f"- {evidence_item}")
    print(f"Final validation status: {final_status}")

    validation_record: UnifiedValidationRecord = {
        "transaction_id": transaction_id,
        "diagnosis_timestamp": diagnosis["timestamp"],
        "permission_timestamp": permission["permission_timestamp"],
        "timestamp": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"
        ),
        "previous_run_id": diagnosis["run_id"],
        "post_change_run_id": post_change_validation[
            "post_change_run_id"
        ],
        "change_file": str(target),
        "expected_files": scope_validation["expected_files"],
        "actual_files": scope_validation["actual_files"],
        "unexpected_files": scope_validation["unexpected_files"],
        "missing_expected_files": scope_validation[
            "missing_expected_files"
        ],
        "change_aware_validation_status": post_change_validation[
            "change_aware_validation_status"
        ],
        "scope_validation_status": scope_validation["scope_status"],
        "final_validation_status": final_status,
        "scope_evidence": scope_validation["evidence"],
        "validation_evidence": post_change_validation[
            "validation_evidence"
        ],
    }

    if not write_validation_result(validation_record):
        final_status = "FAILED"

    if final_status == "PASSED":
        print(
            "Change successful."
        )
        print("All required validation stages passed.")
        return True

    print(
        f"Change was not accepted: validation status is {final_status}."
    )
    print(
        "Restoring the original file..."
    )

    rollback_succeeded = restore_original_file(
        target,
        original_content,
    )

    print()

    if rollback_succeeded:
        print(
            "Rollback successful."
        )
        print(
            "The original file has been restored."
        )
        print(
            "Change is not considered successful."
        )
        return False

    print(
        "The change is NOT considered successful."
    )
    print(
        "The original file could not be restored."
    )

    return False


def main() -> None:
    diagnosis = load_latest_diagnosis()

    if diagnosis is None:
        print(
            "No valid diagnosis found."
        )
        return

    permission = load_latest_permission()

    if not can_apply_change(
        diagnosis,
        permission,
    ):
        print(
            "No matching approved permission found."
        )
        print(
            "No files have been modified."
        )
        return

    apply_change(
        diagnosis,
        permission,
    )


if __name__ == "__main__":
    main()