from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
import subprocess
import time


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
ERROR_LOG_FILE = LOG_FOLDER / "errors.jsonl"

NO_ERROR_EXIT_CODES = {0, 5}
COMMAND_TIMEOUT_SECONDS = 300


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int
    output: str
    duration: float


def write_error(result: CommandResult) -> None:
    LOG_FOLDER.mkdir(parents=True, exist_ok=True)

    error_data: dict[str, object] = {
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "command": result.command,
        "exit_code": result.exit_code,
        "duration_seconds": round(result.duration, 3),
        "output": result.output,
    }

    with ERROR_LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(error_data) + "\n")


def run_command(command: list[str]) -> CommandResult:
    start_time = time.perf_counter()

    try:
        process = subprocess.run(
            command,
            cwd=PROJECT_FOLDER,
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )

    except subprocess.TimeoutExpired as error:
        duration = time.perf_counter() - start_time

        output = (
            "Command timed out after "
            f"{COMMAND_TIMEOUT_SECONDS} seconds."
        )

        if error.stdout:
            output += f"\n{error.stdout}"

        if error.stderr:
            output += f"\n{error.stderr}"

        result = CommandResult(
            command=command,
            exit_code=-1,
            output=output,
            duration=duration,
        )

        write_error(result)
        return result

    except OSError as error:
        duration = time.perf_counter() - start_time

        result = CommandResult(
            command=command,
            exit_code=-1,
            output=str(error),
            duration=duration,
        )

        write_error(result)
        return result

    duration = time.perf_counter() - start_time

    stdout = process.stdout or ""
    stderr = process.stderr or ""

    output = stdout

    if stderr:
        if output:
            output += "\n"
        output += stderr

    result = CommandResult(
        command=command,
        exit_code=process.returncode,
        output=output,
        duration=duration,
    )

    if process.returncode not in NO_ERROR_EXIT_CODES:
        write_error(result)

    return result


def run_with_error_capture(command: list[str]) -> int:
    result = run_command(command)

    print(f"Running: {' '.join(result.command)}")

    if result.exit_code == 0:
        print("Command completed successfully.")
    elif result.exit_code == 5:
        print("No tests were collected.")
        print("This is not considered an error.")
    else:
        print(f"Error evidence written to: {ERROR_LOG_FILE}")

    return result.exit_code


def main() -> None:
    command = ["python", "-m", "pytest"]

    result = run_command(command)

    print()
    print("=" * 50)
    print("AI DEVELOPER OVERSEER - RUNTIME")
    print("=" * 50)
    print(f"Command: {' '.join(result.command)}")
    print(f"Exit code: {result.exit_code}")
    print(f"Duration: {result.duration:.3f} seconds")

    if result.exit_code == 0:
        print("Status: SUCCESS")
    elif result.exit_code == 5:
        print("Status: NO_TESTS")
    else:
        print("Status: ERROR")
        print(f"Error evidence: {ERROR_LOG_FILE}")


if __name__ == "__main__":
    main()