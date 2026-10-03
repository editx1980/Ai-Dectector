from datetime import datetime
from pathlib import Path
from typing import cast
import json

from evidence_models import (
    EvidenceGroup,
    EvidenceRecord,
    EvidenceRelationship,
    append_evidence_group,
    append_evidence_relationship,
    make_evidence_group,
    make_evidence_relationship,
    read_evidence_records,
)


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

SESSIONS_FILE = LOG_FOLDER / "sessions.jsonl"
TEST_RESULTS_FILE = LOG_FOLDER / "test_results.jsonl"
ERRORS_FILE = LOG_FOLDER / "errors.jsonl"
STATIC_ANALYSIS_FILE = LOG_FOLDER / "static_analysis.jsonl"
EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"
RELATIONSHIP_FILE = LOG_FOLDER / "evidence_relationships.jsonl"
GROUP_FILE = LOG_FOLDER / "evidence_groups.jsonl"

CORRELATION_WINDOW_SECONDS = 300


JsonObject = dict[str, object]


def to_json_object(value: object) -> JsonObject | None:
    if not isinstance(value, dict):
        return None

    object_value = cast(dict[object, object], value)

    for key in object_value:
        if not isinstance(key, str):
            return None

    return cast(JsonObject, value)


def load_jsonl(path: Path) -> list[JsonObject]:
    if not path.exists():
        return []

    records: list[JsonObject] = []

    try:
        with path.open("r", encoding="utf-8") as file:
            for line in file:
                stripped_line = line.strip()

                if not stripped_line:
                    continue

                try:
                    data: object = json.loads(stripped_line)
                except json.JSONDecodeError:
                    continue

                record = to_json_object(data)

                if record is not None:
                    records.append(record)

    except OSError:
        return []

    return records


def _normalize_evidence_record(raw: JsonObject) -> EvidenceRecord | None:
    evidence_id = raw.get("evidence_id")
    if not isinstance(evidence_id, str):
        return None

    message = raw.get("message")
    if not isinstance(message, str):
        return None

    project_scope = raw.get("project_scope")
    if not isinstance(project_scope, str):
        project_scope = "project-root"

    affected_files = raw.get("affected_files")
    affected: list[str] = []
    if isinstance(affected_files, list):
        for value in affected_files:
            if isinstance(value, str):
                affected.append(value)

    timestamp = raw.get("timestamp")
    if not isinstance(timestamp, str):
        timestamp = datetime.now().isoformat(timespec="microseconds")

    record: EvidenceRecord = {
        "evidence_id": evidence_id,
        "project_scope": project_scope,
        "affected_files": affected,
        "message": message,
        "correlation_keys": [],
        "related_evidence_ids": [],
        "timestamp": timestamp,
    }

    if isinstance(raw.get("tool_name"), str):
        record["tool_name"] = raw["tool_name"]
    if isinstance(raw.get("evidence_type"), str):
        record["evidence_type"] = raw["evidence_type"]
    if isinstance(raw.get("proof_strength"), str):
        record["proof_strength"] = raw["proof_strength"]
    if isinstance(raw.get("status"), str):
        record["status"] = raw["status"]
    if isinstance(raw.get("run_id"), str):
        record["run_id"] = raw["run_id"]
    if isinstance(raw.get("transaction_id"), str):
        record["transaction_id"] = raw["transaction_id"]
    if isinstance(raw.get("code_location"), str):
        record["code_location"] = raw["code_location"]
    if isinstance(raw.get("error_signature"), str):
        record["error_signature"] = raw["error_signature"]
    if isinstance(raw.get("severity"), str):
        record["severity"] = raw["severity"]
    if isinstance(raw.get("raw_reference"), str):
        record["raw_reference"] = raw["raw_reference"]
    if isinstance(raw.get("availability_note"), str):
        record["availability_note"] = raw["availability_note"]
    if isinstance(raw.get("language"), str):
        record["language"] = raw["language"]
    if isinstance(raw.get("tool_version"), str):
        record["tool_version"] = raw["tool_version"]
    if isinstance(raw.get("correlation_keys"), list):
        record["correlation_keys"] = [
            value for value in raw["correlation_keys"] if isinstance(value, str)
        ]
    if isinstance(raw.get("related_evidence_ids"), list):
        record["related_evidence_ids"] = [
            value for value in raw["related_evidence_ids"] if isinstance(value, str)
        ]
    return record


def _record_timestamp(record: EvidenceRecord) -> datetime | None:
    value = record.get("timestamp")
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _evidence_files(record: EvidenceRecord) -> set[str]:
    files = record.get("affected_files", [])
    if not isinstance(files, list):
        return set()
    return {value for value in files if isinstance(value, str)}


def _relationship_strength(first: EvidenceRecord, second: EvidenceRecord) -> str:
    values = [
        first.get("proof_strength", "LOW"),
        second.get("proof_strength", "LOW"),
    ]
    if any(value == "OBSERVED" for value in values):
        return "OBSERVED"
    if any(value == "HIGH" for value in values):
        return "HIGH"
    if any(value == "MEDIUM" for value in values):
        return "MEDIUM"
    if any(value == "LOW" for value in values):
        return "LOW"
    return "NONE"


def _relationship_key(
    source: EvidenceRecord,
    target: EvidenceRecord,
    relationship_type: str,
    reason: str,
) -> str:
    return f"{source['evidence_id']}|{target['evidence_id']}|{relationship_type}|{reason}"


def correlate_evidence_records(
    records: list[EvidenceRecord],
) -> tuple[list[EvidenceRelationship], list[EvidenceGroup]]:
    if not records:
        return [], []

    seen: set[str] = set()
    relationships: list[EvidenceRelationship] = []

    for index, left in enumerate(records):
        for right in records[index + 1:]:
            if left["evidence_id"] == right["evidence_id"]:
                continue

            pair_signals: list[tuple[str, str, list[str]]] = []

            left_run = left.get("run_id")
            right_run = right.get("run_id")
            if isinstance(left_run, str) and left_run and left_run == right_run:
                pair_signals.append(("RELATED_TO", "shared run_id", ["shared_run_id"]))

            left_txn = left.get("transaction_id")
            right_txn = right.get("transaction_id")
            if isinstance(left_txn, str) and left_txn and left_txn == right_txn:
                pair_signals.append(("RELATED_TO_CHANGE", "shared transaction_id", ["shared_transaction_id"]))

            shared_files = _evidence_files(left).intersection(_evidence_files(right))
            if shared_files:
                pair_signals.append(("RELATED_TO", "shared affected file", ["shared_affected_file", *sorted(shared_files)]))

            if left.get("code_location") == right.get("code_location") and isinstance(left.get("code_location"), str):
                pair_signals.append(("RELATED_TO", "same code location", ["same_code_location"]))

            if left.get("error_signature") and left.get("error_signature") == right.get("error_signature"):
                pair_signals.append(("RELATED_TO", "matching error signature", ["matching_error_signature"]))

            left_ts = _record_timestamp(left)
            right_ts = _record_timestamp(right)
            if left_ts is not None and right_ts is not None:
                if right_ts > left_ts:
                    pair_signals.append(("OBSERVED_BEFORE", "temporal ordering", ["temporal_before"]))
                elif left_ts > right_ts:
                    pair_signals.append(("OBSERVED_AFTER", "temporal ordering", ["temporal_after"]))

            if (
                left.get("status") == "UNAVAILABLE"
                and right.get("status") == "AVAILABLE"
                and bool(shared_files)
            ):
                pair_signals.append(("CONTRADICTS", "tool availability conflicts with observed evidence", ["availability_conflict"]))

            if not pair_signals:
                continue

            for relationship_type, reason, signals in pair_signals:
                relationship_id = _relationship_key(left, right, relationship_type, reason)
                if relationship_id in seen:
                    continue
                seen.add(relationship_id)
                relationship = make_evidence_relationship(
                    source_evidence_id=left["evidence_id"],
                    target_evidence_id=right["evidence_id"],
                    relationship_type=relationship_type,
                    reason=reason,
                    signals=signals,
                    strength=_relationship_strength(left, right),
                    timestamp=left.get("timestamp") if isinstance(left.get("timestamp"), str) else right.get("timestamp"),
                    run_id=left.get("run_id") if isinstance(left.get("run_id"), str) else right.get("run_id"),
                    transaction_id=left.get("transaction_id") if isinstance(left.get("transaction_id"), str) else right.get("transaction_id"),
                    source_file=next(iter(shared_files), left.get("code_location") if isinstance(left.get("code_location"), str) else None),
                    target_file=next(iter(shared_files), right.get("code_location") if isinstance(right.get("code_location"), str) else None),
                )
                relationships.append(relationship)

    if not relationships:
        return [], []

    graph: dict[str, set[str]] = {}
    for relationship in relationships:
        source_id = relationship["source_evidence_id"]
        target_id = relationship["target_evidence_id"]
        graph.setdefault(source_id, set()).add(target_id)
        graph.setdefault(target_id, set()).add(source_id)

    visited: set[str] = set()
    groups: list[EvidenceGroup] = []
    for evidence_id in sorted(graph):
        if evidence_id in visited:
            continue
        queue = [evidence_id]
        component: list[str] = []
        while queue:
            current = queue.pop()
            if current in visited:
                continue
            visited.add(current)
            component.append(current)
            for neighbor in sorted(graph.get(current, set())):
                if neighbor not in visited:
                    queue.append(neighbor)

        if len(component) < 2:
            continue

        component_set = set(component)
        component_relationships = [
            relationship for relationship in relationships
            if relationship["source_evidence_id"] in component_set
            and relationship["target_evidence_id"] in component_set
        ]

        component_records = [record for record in records if record["evidence_id"] in component_set]
        timestamps = [
            _record_timestamp(record)
            for record in component_records
            if _record_timestamp(record) is not None
        ]
        first_seen = min(timestamps) if timestamps else None
        last_seen = max(timestamps) if timestamps else None

        run_ids = {
            record.get("run_id") for record in component_records if isinstance(record.get("run_id"), str)
        }
        transactions = {
            record.get("transaction_id") for record in component_records if isinstance(record.get("transaction_id"), str)
        }
        group = make_evidence_group(
            evidence_ids=sorted(component),
            relationship_ids=[relationship["relationship_id"] for relationship in component_relationships],
            summary=f"Evidence cluster with {len(component)} related records",
            first_seen=(first_seen.isoformat() if first_seen is not None else datetime.now().isoformat(timespec="microseconds")),
            last_seen=(last_seen.isoformat() if last_seen is not None else datetime.now().isoformat(timespec="microseconds")),
            contradiction_count=sum(1 for relationship in component_relationships if relationship["relationship_type"] == "CONTRADICTS"),
            run_id=next(iter(sorted(run_ids)), None),
            transaction_id=next(iter(sorted(transactions)), None),
            temporal_context="AROUND" if first_seen is not None and last_seen is not None else "UNKNOWN",
        )
        groups.append(group)

    return relationships, groups


def persist_correlated_evidence(
    records: list[EvidenceRecord],
    *,
    relationship_path: str | Path = RELATIONSHIP_FILE,
    group_path: str | Path = GROUP_FILE,
) -> tuple[list[EvidenceRelationship], list[EvidenceGroup]]:
    relationships, groups = correlate_evidence_records(records)
    LOG_FOLDER.mkdir(parents=True, exist_ok=True)
    relationship_file = Path(relationship_path)
    group_file = Path(group_path)

    seen_relationships: set[str] = set()
    if relationship_file.exists():
        for existing in read_evidence_records(relationship_file):
            if "relationship_id" in existing:
                seen_relationships.add(str(existing["relationship_id"]))

    for relationship in relationships:
        relation_id = relationship["relationship_id"]
        if relation_id in seen_relationships:
            continue
        append_evidence_relationship(relationship_file, relationship)
        seen_relationships.add(relation_id)

    seen_groups: set[str] = set()
    if group_file.exists():
        for existing in read_evidence_records(group_file):
            if "group_id" in existing:
                seen_groups.add(str(existing["group_id"]))

    for group in groups:
        group_id = group["group_id"]
        if group_id in seen_groups:
            continue
        append_evidence_group(group_file, group)
        seen_groups.add(group_id)

    return relationships, groups


def load_correlated_evidence(
    *,
    relationship_path: str | Path = RELATIONSHIP_FILE,
    group_path: str | Path = GROUP_FILE,
) -> tuple[list[EvidenceRelationship], list[EvidenceGroup]]:
    return (
        read_evidence_relationships(Path(relationship_path)),
        read_evidence_groups(Path(group_path)),
    )


def read_evidence_relationships(path: Path) -> list[EvidenceRelationship]:
    records: list[EvidenceRelationship] = []
    for entry in load_jsonl(path):
        if isinstance(entry, dict) and "relationship_id" in entry:
            records.append(cast(EvidenceRelationship, entry))
    return records


def read_evidence_groups(path: Path) -> list[EvidenceGroup]:
    records: list[EvidenceGroup] = []
    for entry in load_jsonl(path):
        if isinstance(entry, dict) and "group_id" in entry:
            records.append(cast(EvidenceGroup, entry))
    return records


def get_static_findings(
    results: list[JsonObject],
) -> list[JsonObject]:
    findings: list[JsonObject] = []

    for result in results:
        findings_value = result.get("findings")

        if not isinstance(findings_value, list):
            continue

        findings_list = cast(
            list[object],
            findings_value,
        )

        for finding_value in findings_list:
            finding = to_json_object(
                finding_value
            )

            if finding is not None:
                findings.append(finding)

    return findings


def parse_timestamp(
    value: object,
) -> datetime | None:
    if not isinstance(value, str):
        return None

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def get_timestamp(
    record: JsonObject,
) -> datetime | None:
    timestamp = parse_timestamp(
        record.get("timestamp")
    )

    if timestamp is not None:
        return timestamp

    return parse_timestamp(
        record.get("started_at")
    )


def get_session_start(
    session: JsonObject,
) -> datetime | None:
    return parse_timestamp(
        session.get("started_at")
    )


def get_session_end(
    session: JsonObject,
) -> datetime | None:
    return parse_timestamp(
        session.get("ended_at")
    )


def find_related_session(
    test_time: datetime,
    sessions: list[JsonObject],
) -> JsonObject | None:
    best_session: JsonObject | None = None
    best_difference: float | None = None

    for session in sessions:
        session_start = get_session_start(session)
        session_end = get_session_end(session)

        if session_start is None or session_end is None:
            continue

        if session_start > test_time:
            continue

        if session_end > test_time:
            continue

        difference = (
            test_time - session_end
        ).total_seconds()

        if difference > CORRELATION_WINDOW_SECONDS:
            continue

        if (
            best_difference is None
            or difference < best_difference
        ):
            best_difference = difference
            best_session = session

    return best_session


def find_related_errors(
    test: JsonObject,
    errors: list[JsonObject],
) -> list[JsonObject]:
    test_run_id = test.get("run_id")

    if isinstance(test_run_id, str):
        related_errors: list[JsonObject] = []

        for error in errors:
            if error.get("run_id") == test_run_id:
                related_errors.append(error)

        return related_errors

    test_time = get_timestamp(test)

    if test_time is None:
        return []

    test_command = test.get("command")
    test_exit_code = test.get("exit_code")

    related_errors = []

    for error in errors:
        error_time = get_timestamp(error)

        if error_time is None:
            continue

        if error_time != test_time:
            continue

        if error.get("command") != test_command:
            continue

        if error.get("exit_code") != test_exit_code:
            continue

        related_errors.append(error)

    return related_errors


def build_evidence(
    sessions: list[JsonObject],
    tests: list[JsonObject],
    errors: list[JsonObject],
    static_findings: list[JsonObject],
) -> list[JsonObject]:
    evidence_records: list[JsonObject] = []

    for test in tests:
        test_time = get_timestamp(test)

        if test_time is None:
            continue

        if not isinstance(test.get("status"), str):
            continue

        related_session = find_related_session(
            test_time,
            sessions,
        )

        related_errors = find_related_errors(
            test,
            errors,
        )

        if related_session is not None:
            relationship = (
                "Test occurred after a related change session."
            )
        else:
            relationship = (
                "No related change session was found."
            )

        evidence: JsonObject = {
            "run_id": test.get("run_id"),
            "timestamp": test_time.isoformat(),
            "test": test,
            "change_session": related_session,
            "errors": related_errors,
            "static_analysis": static_findings,
            "relationship": relationship,
        }

        evidence_records.append(evidence)

    return evidence_records


def write_evidence(
    records: list[JsonObject],
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    with EVIDENCE_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        for record in records:
            file.write(
                json.dumps(record) + "\n"
            )


def get_string(
    record: JsonObject,
    key: str,
) -> str:
    value = record.get(key)

    if isinstance(value, str):
        return value

    return str(value)


def get_list_length(
    record: JsonObject,
    key: str,
) -> int:
    value = record.get(key)

    if not isinstance(value, list):
        return 0

    list_value = cast(list[object], value)

    return len(list_value)


def print_test_info(
    test: JsonObject,
) -> None:
    print(f"  Test: {test.get('command')}")
    print(f"  Run ID: {test.get('run_id')}")
    print(f"  Status: {test.get('status')}")

    test_time = get_timestamp(test)

    print(
        f"  Time: {test_time.isoformat()}"
        if test_time is not None
        else "  Time: Unknown"
    )


def print_session_info(
    session: JsonObject,
) -> None:
    print("  Related change session: YES")
    print(
        f"  Session: {session.get('session_number')}"
    )
    print(
        f"  Start: {session.get('started_at')}"
    )
    print(
        f"  End: {session.get('ended_at')}"
    )


def print_evidence(
    records: list[JsonObject],
) -> None:
    print()
    print("=" * 50)
    print("AI DEVELOPER OVERSEER - EVIDENCE")
    print("=" * 50)

    if not records:
        print()
        print("No test evidence found.")
        return

    for index, record in enumerate(
        records,
        start=1,
    ):
        print()
        print(f"Evidence #{index}")

        test_value = record.get("test")
        test = to_json_object(test_value)

        if test is not None:
            print_test_info(test)

        session_value = record.get(
            "change_session"
        )

        session = to_json_object(
            session_value
        )

        if session is not None:
            print_session_info(session)
        else:
            print(
                "  Related change session: NO"
            )

        error_count = get_list_length(
            record,
            "errors",
        )

        print(
            f"  Related errors: {error_count}"
        )

        static_analysis_count = get_list_length(
            record,
            "static_analysis",
        )

        print(
            "  Static analysis findings: "
            f"{static_analysis_count}"
        )

        relationship = get_string(
            record,
            "relationship",
        )

        print(
            f"  Relationship: {relationship}"
        )


def main() -> None:
    sessions = load_jsonl(
        SESSIONS_FILE
    )

    tests = load_jsonl(
        TEST_RESULTS_FILE
    )

    tests = tests[-1:]

    errors = load_jsonl(
        ERRORS_FILE
    )

    static_analysis = load_jsonl(
        STATIC_ANALYSIS_FILE
    )

    static_findings = get_static_findings(
        static_analysis
    )

    evidence = build_evidence(
        sessions=sessions,
        tests=tests,
        errors=errors,
        static_findings=static_findings,
    )

    write_evidence(evidence)
    print_evidence(evidence)

    print()
    print(
        f"Evidence file: {EVIDENCE_FILE}"
    )


if __name__ == "__main__":
    main()