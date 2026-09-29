from datetime import datetime
from pathlib import Path
from typing import cast
import json


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

SESSIONS_FILE = LOG_FOLDER / "sessions.jsonl"
TEST_RESULTS_FILE = LOG_FOLDER / "test_results.jsonl"
ERRORS_FILE = LOG_FOLDER / "errors.jsonl"
EVIDENCE_FILE = LOG_FOLDER / "evidence.jsonl"

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
    test_time = get_timestamp(test)

    if test_time is None:
        return []

    test_command = test.get("command")
    test_exit_code = test.get("exit_code")

    related_errors: list[JsonObject] = []

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
) -> list[JsonObject]:
    evidence_records: list[JsonObject] = []

    for test in tests:
        test_time = get_timestamp(test)

        if test_time is None:
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
            "timestamp": test_time.isoformat(),
            "test": test,
            "change_session": related_session,
            "errors": related_errors,
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

    errors = load_jsonl(
        ERRORS_FILE
    )

    evidence = build_evidence(
        sessions=sessions,
        tests=tests,
        errors=errors,
    )

    write_evidence(evidence)
    print_evidence(evidence)

    print()
    print(
        f"Evidence file: {EVIDENCE_FILE}"
    )


if __name__ == "__main__":
    main()