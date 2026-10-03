from __future__ import annotations

import json
from pathlib import Path

from evidence_models import read_evidence_records
from evidence_normalizer import (
    normalize_detector_results,
    normalize_runtime_error,
    normalize_static_analysis_record,
    normalize_test_result,
)


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False))
            handle.write("\n")


def test_normalize_static_analysis_result_to_static_warning() -> None:
    raw = {
        "tool": "ruff",
        "language": "Python",
        "available": True,
        "exit_code": 1,
        "findings": [
            {
                "tool": "ruff",
                "language": "Python",
                "severity": "WARNING",
                "message": "Unused import: os",
                "file": "src/example.py",
                "line": 4,
                "column": 1,
                "raw_output": "src/example.py:4:1: F401 'os' imported but unused",
            }
        ],
    }

    records = normalize_static_analysis_record(raw)
    assert len(records) == 1
    assert records[0]["evidence_type"] == "STATIC_WARNING"
    assert records[0]["status"] == "AVAILABLE"
    assert records[0]["affected_files"] == ["src/example.py"]
    assert records[0]["code_location"] == "src/example.py:4:1"


def test_normalize_failed_test_result_to_test_failure() -> None:
    raw = {
        "run_id": "run-123",
        "timestamp": "2026-10-03T12:00:00Z",
        "command": ["python", "-m", "pytest"],
        "source": "overseer.json",
        "exit_code": 1,
        "status": "FAILED",
        "duration_seconds": 0.5,
        "output": "============================= FAILURES =============================\n________________ test_example __________________\nE   assert 1 == 2",
        "failures": [{"file": "test_example.py", "line": 5, "test": "test_example"}],
    }

    records = normalize_test_result(raw)
    assert len(records) == 1
    assert records[0]["evidence_type"] == "TEST_FAILURE"
    assert records[0]["proof_strength"] == "HIGH"
    assert records[0]["run_id"] == "run-123"
    assert records[0]["affected_files"] == ["test_example.py"]


def test_normalize_runtime_error_to_runtime_error_record() -> None:
    raw = {
        "timestamp": "2026-10-03T12:00:00Z",
        "command": ["python", "script.py"],
        "exit_code": 1,
        "duration_seconds": 0.1,
        "output": "Traceback (most recent call last):\n  File \"script.py\", line 10, in <module>\n    raise ValueError('bad')\nValueError: bad",
    }

    records = normalize_runtime_error(raw)
    assert len(records) == 1
    assert records[0]["evidence_type"] == "RUNTIME_ERROR"
    assert records[0]["status"] == "AVAILABLE"
    assert records[0]["severity"] == "HIGH"
    assert records[0]["affected_files"] == ["script.py"]


def test_unavailable_tool_is_not_interpreted_as_clean() -> None:
    raw = {
        "tool": "tsc",
        "language": "TypeScript",
        "available": False,
        "exit_code": None,
        "findings": [],
    }

    records = normalize_static_analysis_record(raw)
    assert len(records) == 1
    assert records[0]["evidence_type"] == "STATIC_WARNING"
    assert records[0]["status"] == "UNAVAILABLE"
    assert records[0]["proof_strength"] == "NONE"


def test_normalized_evidence_persists_to_jsonl_and_reads_back() -> None:
    path = Path("logs/test_normalized_evidence.jsonl")
    if path.exists():
        path.unlink()

    rows = [
        {
            "tool": "ruff",
            "language": "Python",
            "available": True,
            "exit_code": 1,
            "findings": [
                {
                    "tool": "ruff",
                    "language": "Python",
                    "severity": "WARNING",
                    "message": "Unused import: os",
                    "file": "src/example.py",
                    "line": 4,
                    "column": 1,
                    "raw_output": "src/example.py:4:1: F401 'os' imported but unused",
                }
            ],
        },
        {
            "run_id": "run-456",
            "status": "FAILED",
            "command": ["python", "-m", "pytest"],
            "output": "FAILED test_example.py::test_example",
            "failures": [{"file": "test_example.py", "line": 7, "test": "test_example"}],
        },
    ]

    _write_jsonl(path, rows)
    target = Path("logs/integration_normalized_evidence.jsonl")
    if target.exists():
        target.unlink()

    combined: list[dict[str, object]] = []
    for row in rows:
        if row.get("findings") is not None:
            combined.extend(normalize_static_analysis_record(row, source_name="test_normalized_evidence.jsonl"))
        else:
            combined.extend(normalize_test_result(row, source_name="test_normalized_evidence.jsonl"))

    for record in combined:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False))
            handle.write("\n")

    persisted = read_evidence_records(target)
    assert len(persisted) == 2
    assert persisted[0]["evidence_type"] == "STATIC_WARNING"
    assert persisted[1]["evidence_type"] == "TEST_FAILURE"


def test_normalize_detector_results_persists_real_project_records() -> None:
    root = Path(".")
    logs_dir = root / "logs"
    static_path = logs_dir / "static_analysis.jsonl"
    tests_path = logs_dir / "test_results.jsonl"
    errors_path = logs_dir / "errors.jsonl"
    evidence_path = logs_dir / "phase2_integration_evidence.jsonl"

    if evidence_path.exists():
        evidence_path.unlink()

    _write_jsonl(static_path, [
        {
            "tool": "Python",
            "language": "Python",
            "available": True,
            "exit_code": 0,
            "findings": [],
        },
        {
            "tool": "ruff",
            "language": "Python",
            "available": True,
            "exit_code": 1,
            "findings": [
                {
                    "tool": "ruff",
                    "language": "Python",
                    "severity": "ERROR",
                    "message": "unused import",
                    "file": "src/alpha.py",
                    "line": 3,
                    "column": 2,
                    "raw_output": "src/alpha.py:3:2: F401 unused import",
                }
            ],
        },
    ])
    _write_jsonl(tests_path, [
        {
            "run_id": "run-999",
            "status": "FAILED",
            "command": ["python", "-m", "pytest"],
            "output": "FAILED src/test_alpha.py::test_alpha",
            "failures": [{"file": "src/test_alpha.py", "line": 8, "test": "test_alpha"}],
        }
    ])
    _write_jsonl(errors_path, [
        {
            "timestamp": "2026-10-03T12:00:00Z",
            "command": ["python", "-m", "pytest"],
            "exit_code": 1,
            "output": "Traceback (most recent call last):\n  File \"src/test_alpha.py\", line 8, in test_alpha\n    assert 1 == 2",
        }
    ])

    records = normalize_detector_results(project_root=root, output_path=evidence_path)
    assert len(records) == 3
    assert {record["evidence_type"] for record in records} == {
        "STATIC_WARNING",
        "TEST_FAILURE",
        "RUNTIME_ERROR",
    }

    persisted = read_evidence_records(evidence_path)
    assert len(persisted) == 3
    assert persisted[0]["tool_name"] in {"ruff", "pytest", "python"}
    assert all("raw_reference" in record for record in persisted)
