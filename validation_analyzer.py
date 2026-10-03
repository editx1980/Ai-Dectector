from __future__ import annotations

from typing import Literal, TypeAlias, TypedDict, cast


TestRunStatus: TypeAlias = Literal[
    "PASSED",
    "FAILED",
    "NO_TESTS",
]

ValidationStatus: TypeAlias = Literal[
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
]

FailureIdentity: TypeAlias = tuple[str, ...]


class TestFailure(TypedDict, total=False):
    file: str
    line: int
    test: str


class TestResult(TypedDict):
    run_id: str
    status: TestRunStatus
    command: list[str]
    failures: list[TestFailure]


class ValidationComparison(TypedDict):
    previous_run_id: str | None
    post_change_run_id: str | None
    original_failure_resolved: bool | None
    same_failures_remain: bool
    new_failures_detected: bool
    validation_status: ValidationStatus
    evidence: list[str]


def parse_test_result(
    value: object,
) -> TestResult | None:
    if not isinstance(value, dict):
        return None

    record = cast(dict[object, object], value)

    if any(not isinstance(key, str) for key in record):
        return None

    run_id = record.get("run_id")
    raw_status = record.get("status")
    raw_command = record.get("command")
    raw_failures = record.get("failures")

    if not isinstance(run_id, str) or not run_id:
        return None

    if raw_status == "PASSED":
        status: TestRunStatus = "PASSED"
    elif raw_status == "FAILED":
        status = "FAILED"
    elif raw_status == "NO_TESTS":
        status = "NO_TESTS"
    else:
        return None

    if not isinstance(raw_command, list):
        return None

    command_values = cast(list[object], raw_command)
    command: list[str] = []

    for item in command_values:
        if not isinstance(item, str):
            return None
        command.append(item)

    if not isinstance(raw_failures, list):
        return None

    failure_values = cast(list[object], raw_failures)
    failures: list[TestFailure] = []

    for failure_value in failure_values:
        failure = parse_test_failure(failure_value)

        if failure is None:
            return None

        failures.append(failure)

    return {
        "run_id": run_id,
        "status": status,
        "command": command,
        "failures": failures,
    }


def parse_test_failure(
    value: object,
) -> TestFailure | None:
    if not isinstance(value, dict):
        return None

    record = cast(dict[object, object], value)

    if any(not isinstance(key, str) for key in record):
        return None

    file_path = record.get("file")
    line = record.get("line")
    test_name = record.get("test")

    if not isinstance(file_path, str) or not file_path:
        return None

    if not isinstance(line, int) or isinstance(line, bool):
        return None

    if test_name is not None and not isinstance(test_name, str):
        return None

    failure: TestFailure = {
        "file": file_path,
        "line": line,
    }

    if isinstance(test_name, str):
        failure["test"] = test_name

    return failure


def normalize_file_path(file_path: str) -> str:
    normalized = file_path.replace("\\", "/")

    while normalized.startswith("./"):
        normalized = normalized[2:]

    return normalized.casefold()


def get_failure_identity(
    failure: TestFailure,
) -> FailureIdentity | None:
    file_path = failure.get("file")

    if file_path is None:
        return None

    normalized_path = normalize_file_path(file_path)
    test_name = failure.get("test")

    if test_name:
        return (
            "test",
            normalized_path,
            test_name.casefold(),
        )

    line = failure.get("line")

    if line is None:
        return None

    return (
        "location",
        normalized_path,
        str(line),
    )


def failure_matches_affected_files(
    failure: TestFailure,
    affected_files: list[str],
) -> bool:
    file_path = failure.get("file")

    if file_path is None:
        return False

    failure_path = normalize_file_path(file_path)

    return any(
        normalize_file_path(affected_file) == failure_path
        for affected_file in affected_files
    )


def compare_test_results(
    previous_result: TestResult | None,
    post_change_result: TestResult | None,
    affected_files: list[str],
) -> ValidationComparison:
    previous_run_id = (
        previous_result["run_id"]
        if previous_result is not None
        else None
    )
    post_change_run_id = (
        post_change_result["run_id"]
        if post_change_result is not None
        else None
    )
    evidence: list[str] = []

    if post_change_result is None:
        evidence.append("No post-change test result is available.")
        return {
            "previous_run_id": previous_run_id,
            "post_change_run_id": None,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": False,
            "validation_status": "FAILED",
            "evidence": evidence,
        }

    if previous_result is not None and (
        post_change_result["run_id"] == previous_result["run_id"]
    ):
        evidence.append(
            "The post-change result reuses the previous run ID."
        )
        return {
            "previous_run_id": previous_run_id,
            "post_change_run_id": post_change_run_id,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": False,
            "validation_status": "FAILED",
            "evidence": evidence,
        }

    if post_change_result["status"] != "PASSED":
        evidence.append(
            "The post-change test run did not pass."
        )

    if previous_result is None:
        evidence.append(
            "The pre-change test result is unavailable for comparison."
        )
        return {
            "previous_run_id": None,
            "post_change_run_id": post_change_run_id,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": bool(
                post_change_result["failures"]
            ),
            "validation_status": (
                "FAILED"
                if post_change_result["status"] != "PASSED"
                else "INCONCLUSIVE"
            ),
            "evidence": evidence,
        }

    if previous_result["status"] != "FAILED":
        evidence.append(
            "The pre-change run does not record a failed test run."
        )
        return {
            "previous_run_id": previous_run_id,
            "post_change_run_id": post_change_run_id,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": bool(
                post_change_result["failures"]
            ),
            "validation_status": (
                "FAILED"
                if post_change_result["status"] != "PASSED"
                else "INCONCLUSIVE"
            ),
            "evidence": evidence,
        }

    if previous_result["command"] != post_change_result["command"]:
        evidence.append(
            "The configured test command changed between runs."
        )
        return {
            "previous_run_id": previous_run_id,
            "post_change_run_id": post_change_run_id,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": bool(
                post_change_result["failures"]
            ),
            "validation_status": (
                "FAILED"
                if post_change_result["status"] != "PASSED"
                else "INCONCLUSIVE"
            ),
            "evidence": evidence,
        }

    previous_failures = previous_result["failures"]
    post_change_failures = post_change_result["failures"]
    relevant_previous_failures = [
        failure
        for failure in previous_failures
        if failure_matches_affected_files(
            failure,
            affected_files,
        )
    ]

    if not relevant_previous_failures:
        evidence.append(
            "No pre-change failure matches the diagnosis's affected files."
        )
        return {
            "previous_run_id": previous_run_id,
            "post_change_run_id": post_change_run_id,
            "original_failure_resolved": None,
            "same_failures_remain": False,
            "new_failures_detected": bool(
                post_change_failures
            ),
            "validation_status": (
                "FAILED"
                if post_change_result["status"] != "PASSED"
                else "INCONCLUSIVE"
            ),
            "evidence": evidence,
        }

    previous_identities = {
        identity
        for failure in previous_failures
        if (identity := get_failure_identity(failure)) is not None
    }
    post_change_identities = {
        identity
        for failure in post_change_failures
        if (identity := get_failure_identity(failure)) is not None
    }
    relevant_identities = {
        identity
        for failure in relevant_previous_failures
        if (identity := get_failure_identity(failure)) is not None
    }
    same_failures_remain = bool(
        relevant_identities & post_change_identities
    )
    new_failures_detected = bool(
        post_change_identities - previous_identities
    )
    original_failure_resolved = not same_failures_remain

    if same_failures_remain:
        evidence.append(
            "At least one diagnosed-file failure remains after the change."
        )
    else:
        evidence.append(
            "The diagnosed-file failure signature is absent after the change."
        )

    if new_failures_detected:
        evidence.append(
            "The post-change run contains failure signatures not seen before."
        )

    if post_change_result["status"] != "PASSED":
        validation_status: ValidationStatus = "FAILED"
    elif post_change_failures:
        evidence.append(
            "The passing result contains failure records, so its evidence conflicts."
        )
        validation_status = "FAILED"
    elif same_failures_remain:
        validation_status = "FAILED"
    else:
        validation_status = "PASSED"

    return {
        "previous_run_id": previous_run_id,
        "post_change_run_id": post_change_run_id,
        "original_failure_resolved": original_failure_resolved,
        "same_failures_remain": same_failures_remain,
        "new_failures_detected": new_failures_detected,
        "validation_status": validation_status,
        "evidence": evidence,
    }
