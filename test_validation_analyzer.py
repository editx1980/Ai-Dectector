import json

import validation_analyzer


def create_failure(
    file_path: str,
    line: int,
    test_name: str,
) -> validation_analyzer.TestFailure:
    return {
        "file": file_path,
        "line": line,
        "test": test_name,
    }


def create_result(
    run_id: str,
    status: validation_analyzer.TestRunStatus,
    failures: list[validation_analyzer.TestFailure],
) -> validation_analyzer.TestResult:
    return {
        "run_id": run_id,
        "status": status,
        "command": ["python", "-m", "pytest"],
        "failures": failures,
    }


def test_failed_before_and_passed_after_resolves_relevant_failure() -> None:
    previous = create_result(
        "before",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )
    post_change = create_result("after", "PASSED", [])

    comparison = validation_analyzer.compare_test_results(
        previous,
        post_change,
        ["tests\\test_total.py"],
    )

    assert comparison["validation_status"] == "PASSED"
    assert comparison["original_failure_resolved"] is True
    assert comparison["same_failures_remain"] is False
    assert comparison["new_failures_detected"] is False


def test_failed_before_and_same_failure_after_is_failed() -> None:
    original_failure = create_failure(
        "tests/test_total.py",
        42,
        "test_total",
    )
    previous = create_result("before", "FAILED", [original_failure])
    post_change = create_result(
        "after",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )

    comparison = validation_analyzer.compare_test_results(
        previous,
        post_change,
        ["tests/test_total.py"],
    )

    assert comparison["validation_status"] == "FAILED"
    assert comparison["original_failure_resolved"] is False
    assert comparison["same_failures_remain"] is True


def test_failed_before_and_different_failure_after_is_not_a_success() -> None:
    previous = create_result(
        "before",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )
    post_change = create_result(
        "after",
        "FAILED",
        [create_failure("tests/test_discount.py", 18, "test_discount")],
    )

    comparison = validation_analyzer.compare_test_results(
        previous,
        post_change,
        ["tests/test_total.py"],
    )

    assert comparison["validation_status"] == "FAILED"
    assert comparison["original_failure_resolved"] is True
    assert comparison["same_failures_remain"] is False
    assert comparison["new_failures_detected"] is True


def test_passed_after_without_matching_pre_change_failure_is_inconclusive() -> None:
    previous = create_result(
        "before",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )
    post_change = create_result("after", "PASSED", [])

    comparison = validation_analyzer.compare_test_results(
        previous,
        post_change,
        ["src/calculator.py"],
    )

    assert comparison["validation_status"] == "INCONCLUSIVE"
    assert comparison["original_failure_resolved"] is None


def test_stale_post_change_run_is_rejected() -> None:
    previous = create_result(
        "same-run",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )
    post_change = create_result("same-run", "PASSED", [])

    comparison = validation_analyzer.compare_test_results(
        previous,
        post_change,
        ["tests/test_total.py"],
    )

    assert comparison["validation_status"] == "FAILED"
    assert comparison["original_failure_resolved"] is None


def test_missing_post_change_result_is_rejected() -> None:
    previous = create_result(
        "before",
        "FAILED",
        [create_failure("tests/test_total.py", 42, "test_total")],
    )

    comparison = validation_analyzer.compare_test_results(
        previous,
        None,
        ["tests/test_total.py"],
    )

    assert comparison["validation_status"] == "FAILED"
    assert comparison["post_change_run_id"] is None


def test_parse_test_result_validates_json_shape() -> None:
    raw_result: object = json.loads(
        '{"run_id":"run-1","status":"FAILED",'
        '"command":["python","-m","pytest"],'
        '"failures":[{"file":"tests/test_total.py",'
        '"line":42,"test":"test_total"}]}'
    )

    result = validation_analyzer.parse_test_result(raw_result)

    assert result is not None
    assert result["run_id"] == "run-1"
    assert result["failures"][0]["test"] == "test_total"


def test_parse_test_result_rejects_invalid_failure_data() -> None:
    raw_result: object = {
        "run_id": "run-1",
        "status": "FAILED",
        "command": ["python", "-m", "pytest"],
        "failures": [{"file": "tests/test_total.py", "line": True}],
    }

    assert validation_analyzer.parse_test_result(raw_result) is None
