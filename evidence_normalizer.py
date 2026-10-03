from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast

from evidence_models import (
    EvidenceRecord,
    append_evidence_record,
    make_evidence_record,
    read_evidence_records,
)

PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
STATIC_ANALYSIS_FILE = LOG_FOLDER / "static_analysis.jsonl"
TEST_RESULTS_FILE = LOG_FOLDER / "test_results.jsonl"
ERRORS_FILE = LOG_FOLDER / "errors.jsonl"
EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"


def _read_jsonl(path: Path) -> list[dict[str, object]]:
    if not path.exists():
        return []

    records: list[dict[str, object]] = []
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(value, dict):
                records.append(cast(dict[str, object], value))
    return records


def _as_string(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _as_string_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    strings: list[str] = []
    for item in value:
        if isinstance(item, str):
            strings.append(item)
    return strings


def _collect_files_from_output(output: str) -> list[str]:
    found: list[str] = []
    for match in re.finditer(r'File "([^"]+)", line \d+', output):
        file_name = match.group(1)
        if file_name and file_name not in found:
            found.append(file_name)
    for match in re.finditer(r"([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+):(\d+)", output):
        file_name = match.group(1)
        if file_name and file_name not in found:
            found.append(file_name)
    return found


def _summarize_message(output: str, fallback: str) -> str:
    if not output:
        return fallback
    for line in output.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return fallback


def _existing_raw_references(path: Path) -> set[str]:
    references: set[str] = set()
    for record in read_evidence_records(path):
        raw_reference = record.get("raw_reference")
        if isinstance(raw_reference, str):
            references.add(raw_reference)
    return references


def normalize_static_analysis_record(
    raw_record: dict[str, object],
    *,
    source_name: str = "static_analysis.jsonl",
    project_scope: str = "project-root",
) -> list[EvidenceRecord]:
    tool_name = _as_string(raw_record.get("tool")) or "static-analysis"
    language = _as_string(raw_record.get("language")) or "Unknown"
    available = bool(raw_record.get("available"))
    findings = raw_record.get("findings")

    if not isinstance(findings, list):
        findings = []

    if not available:
        record = make_evidence_record(
            evidence_type="STATIC_WARNING",
            tool_name=tool_name,
            project_scope=project_scope,
            message=f"Tool unavailable: {tool_name}",
            proof_strength="NONE",
            status="UNAVAILABLE",
            language=language,
            availability_note="Static analysis tool was not available in the current environment.",
            raw_reference=f"{source_name}:tool:{tool_name}",
        )
        return [record]

    normalized: list[EvidenceRecord] = []
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict):
            continue

        message = _as_string(finding.get("message")) or "Static analysis finding"
        file_name = _as_string(finding.get("file"))
        line_number = finding.get("line")
        column_number = finding.get("column")
        raw_output = _as_string(finding.get("raw_output")) or message
        severity_value = _as_string(finding.get("severity")) or "WARNING"
        severity = "HIGH" if severity_value.upper() == "ERROR" else "MEDIUM"

        code_location = None
        if file_name is not None:
            code_location = file_name
            if isinstance(line_number, int):
                code_location = f"{file_name}:{line_number}"
                if isinstance(column_number, int):
                    code_location = f"{code_location}:{column_number}"

        normalized.append(
            make_evidence_record(
                evidence_type="STATIC_WARNING",
                tool_name=tool_name,
                project_scope=project_scope,
                message=message,
                affected_files=[file_name] if file_name else [],
                proof_strength="LOW",
                status="AVAILABLE",
                language=language,
                code_location=code_location,
                error_signature=raw_output[:200],
                severity=severity,
                raw_reference=f"{source_name}:{tool_name}:{index}",
                correlation_keys=[tool_name, file_name] if file_name else [tool_name],
            )
        )

    return normalized


def normalize_test_result(
    raw_record: dict[str, object],
    *,
    source_name: str = "test_results.jsonl",
    project_scope: str = "project-root",
) -> list[EvidenceRecord]:
    status = _as_string(raw_record.get("status")) or "UNKNOWN"
    if status != "FAILED":
        return []

    command = _as_string_list(raw_record.get("command"))
    tool_name = command[0] if command else "pytest"
    run_id = _as_string(raw_record.get("run_id"))
    output = _as_string(raw_record.get("output")) or ""
    failures = raw_record.get("failures")
    files: list[str] = []
    tests: list[str] = []

    if isinstance(failures, list):
        for item in failures:
            if not isinstance(item, dict):
                continue
            file_name = _as_string(item.get("file"))
            if file_name and file_name not in files:
                files.append(file_name)
            test_name = _as_string(item.get("test"))
            if test_name and test_name not in tests:
                tests.append(test_name)

    message = _summarize_message(output, f"Test run failed with status {status}.")
    evidence = make_evidence_record(
        evidence_type="TEST_FAILURE",
        tool_name=tool_name,
        project_scope=project_scope,
        message=message,
        affected_files=files,
        proof_strength="HIGH",
        status="AVAILABLE",
        severity="HIGH",
        run_id=run_id,
        error_signature="|".join(tests) if tests else None,
        raw_reference=f"{source_name}:{run_id}" if run_id else f"{source_name}:failed-test",
        correlation_keys=tests or [tool_name],
    )
    return [evidence]


def normalize_runtime_error(
    raw_record: dict[str, object],
    *,
    source_name: str = "errors.jsonl",
    project_scope: str = "project-root",
) -> list[EvidenceRecord]:
    command = _as_string_list(raw_record.get("command"))
    tool_name = command[0] if command else "runtime-monitor"
    output = _as_string(raw_record.get("output")) or ""
    exit_code = raw_record.get("exit_code")
    files = _collect_files_from_output(output)
    message = _summarize_message(output, f"Command failed with exit code {exit_code}.")
    severity = "HIGH" if isinstance(exit_code, int) and exit_code != 0 else "MEDIUM"
    evidence = make_evidence_record(
        evidence_type="RUNTIME_ERROR",
        tool_name=tool_name,
        project_scope=project_scope,
        message=message,
        affected_files=files,
        proof_strength="MEDIUM",
        status="AVAILABLE",
        severity=severity,
        error_signature=_summarize_message(output, str(exit_code))[:200],
        raw_reference=f"{source_name}:{tool_name}:{_as_string(raw_record.get('timestamp')) or 'runtime-error'}",
        correlation_keys=[tool_name, *files],
    )
    return [evidence]


def normalize_detector_results(
    *,
    project_root: str | Path | None = None,
    output_path: str | Path | None = None,
) -> list[EvidenceRecord]:
    root = Path(project_root) if project_root is not None else PROJECT_FOLDER
    target_path = Path(output_path) if output_path is not None else EVIDENCE_FILE
    records: list[EvidenceRecord] = []

    for raw_record in _read_jsonl(root / "logs" / "static_analysis.jsonl"):
        records.extend(normalize_static_analysis_record(raw_record, source_name="static_analysis.jsonl"))

    for raw_record in _read_jsonl(root / "logs" / "test_results.jsonl"):
        records.extend(normalize_test_result(raw_record, source_name="test_results.jsonl"))

    for raw_record in _read_jsonl(root / "logs" / "errors.jsonl"):
        records.extend(normalize_runtime_error(raw_record, source_name="errors.jsonl"))

    seen_refs = _existing_raw_references(target_path)
    persisted: list[EvidenceRecord] = []
    for record in records:
        raw_reference = record.get("raw_reference")
        if isinstance(raw_reference, str) and raw_reference in seen_refs:
            continue
        appended = append_evidence_record(target_path, record)
        persisted.append(appended)
        if isinstance(raw_reference, str):
            seen_refs.add(raw_reference)
    return persisted


def main() -> None:
    records = normalize_detector_results(project_root=PROJECT_FOLDER)
    print(f"Normalized {len(records)} evidence records into {EVIDENCE_FILE}")


if __name__ == "__main__":
    main()
