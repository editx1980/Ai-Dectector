from datetime import datetime
from pathlib import Path
import json
import re
import uuid
from typing import cast

from runtime_monitor import run_command


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
RESULT_LOG_FILE = LOG_FOLDER / "test_results.jsonl"
CONFIG_FILE = PROJECT_FOLDER / "overseer.json"
PROFILE_FILE = LOG_FOLDER / "project_profile.json"


def load_json_file(
    path: Path,
) -> dict[str, object] | None:
    if not path.exists():
        return None

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = json.load(file)
    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    if not isinstance(data, dict):
        return None

    return cast(
        dict[str, object],
        data,
    )


def get_configured_command() -> tuple[
    list[str] | None,
    str | None,
]:
    data = load_json_file(
        CONFIG_FILE
    )

    if data is None:
        return None, None

    raw_command = data.get(
        "test_command"
    )

    if not isinstance(
        raw_command,
        list,
    ):
        return None, None

    command_items = cast(
        list[object],
        raw_command,
    )

    command: list[str] = []

    for item in command_items:
        if not isinstance(
            item,
            str,
        ):
            return None, None

        command.append(item)

    if not command:
        return None, None

    return command, "overseer.json"


def get_discovered_command() -> tuple[
    list[str] | None,
    str | None,
]:
    data = load_json_file(
        PROFILE_FILE
    )

    if data is None:
        return None, None

    raw_strategies = data.get(
        "test_strategies"
    )

    if not isinstance(
        raw_strategies,
        list,
    ):
        return None, None

    strategies = cast(
        list[object],
        raw_strategies,
    )

    for raw_strategy in strategies:
        if not isinstance(
            raw_strategy,
            dict,
        ):
            continue

        strategy = cast(
            dict[str, object],
            raw_strategy,
        )

        raw_command = strategy.get(
            "command"
        )

        framework = strategy.get(
            "framework"
        )

        if not isinstance(
            raw_command,
            list,
        ):
            continue

        if not isinstance(
            framework,
            str,
        ):
            continue

        command_items = cast(
            list[object],
            raw_command,
        )

        command: list[str] = []
        valid = True

        for item in command_items:
            if not isinstance(
                item,
                str,
            ):
                valid = False
                break

            command.append(item)

        if valid and command:
            return (
                command,
                f"project discovery ({framework})",
            )

    return None, None


def determine_test_command() -> tuple[
    list[str] | None,
    str | None,
]:
    command, source = (
        get_configured_command()
    )

    if command is not None:
        return command, source

    return get_discovered_command()


def determine_status(
    exit_code: int,
) -> str:
    if exit_code == 0:
        return "PASSED"

    if exit_code == 5:
        return "NO_TESTS"

    return "FAILED"


def extract_failures(
    output: str,
) -> list[dict[str, object]]:
    failures: list[
        dict[str, object]
    ] = []

    current_test: str | None = None

    for line in output.splitlines():
        test_match = re.search(
            r"_{5,}\s+([A-Za-z0-9_]+)\s+_{5,}",
            line,
        )

        if test_match is not None:
            current_test = (
                test_match.group(1)
            )

        location_match = re.search(
            r"([^\s:]+\.py):(\d+):",
            line,
        )

        if location_match is None:
            continue

        file_path = location_match.group(1)

        line_number = int(
            location_match.group(2)
        )

        failure: dict[str, object] = {
            "file": file_path,
            "line": line_number,
        }

        if current_test is not None:
            failure["test"] = (
                current_test
            )

        duplicate = any(
            existing.get("file")
            == file_path
            and existing.get("line")
            == line_number
            and existing.get("test")
            == failure.get("test")
            for existing in failures
        )

        if duplicate:
            continue

        failures.append(
            failure
        )

    return failures


def write_result(
    run_id: str,
    command: list[str],
    source: str,
    exit_code: int,
    status: str,
    output: str,
    duration: float,
    failures: list[
        dict[str, object]
    ],
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    result: dict[str, object] = {
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(
            timespec="milliseconds"
        ),
        "command": command,
        "source": source,
        "exit_code": exit_code,
        "status": status,
        "duration_seconds": round(
            duration,
            3,
        ),
        "output": output,
        "failures": failures,
    }

    with RESULT_LOG_FILE.open(
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(
                result
            )
            + "\n"
        )


def run_test() -> None:
    run_id = str(uuid.uuid4())

    command, source = (
        determine_test_command()
    )

    if (
        command is None
        or source is None
    ):
        print(
            "No test strategy detected."
        )
        print(
            "No test was run."
        )
        return

    print(
        f"Running test: "
        f"{' '.join(command)}"
    )

    print(
        f"Strategy source: {source}"
    )

    result = run_command(
        command
    )

    status = determine_status(
        result.exit_code
    )

    failures = extract_failures(
        result.output
    )

    write_result(
        run_id=run_id,
        command=result.command,
        source=source,
        exit_code=result.exit_code,
        status=status,
        output=result.output,
        duration=result.duration,
        failures=failures,
    )

    print()
    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - TEST"
    )
    print("=" * 50)
    print()

    print(
        f"Command: "
        f"{' '.join(result.command)}"
    )

    print(
        f"Source: {source}"
    )

    print(
        f"Exit code: "
        f"{result.exit_code}"
    )

    print(
        f"Status: {status}"
    )

    print(
        f"Duration: "
        f"{result.duration:.3f} seconds"
    )

    print()

    print(
        f"Failures detected: "
        f"{len(failures)}"
    )

    for failure in failures:
        print(
            f"  {failure.get('file')}:"
            f"{failure.get('line')}"
        )

    print()

    print("Output:")
    print(result.output)

    print("-" * 50)


def main() -> None:
    run_test()


if __name__ == "__main__":
    main()