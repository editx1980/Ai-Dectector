from pathlib import Path
from datetime import datetime
from queue import Queue, Empty
import json
import subprocess
import sys
import time

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
LOG_FILE = LOG_FOLDER / "events.jsonl"
TEST_RESULTS_FILE = LOG_FOLDER / "test_results.jsonl"

PIPELINE_COOLDOWN_SECONDS = 1.0
EVENT_DEBOUNCE_SECONDS = 0.5

SOURCE_EXTENSIONS = {
    ".py",
    ".pyw",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".lua",
    ".luau",
}

INTERNAL_FILES = {
    "main.py",
    "tester.py",
    "evidence_correlator.py",
    "ai_diagnoser.py",
    "permission_manager.py",
    "change_applier.py",
    "project_scanner.py",
    "project_context.py",
    "static_analyzer.py",
    "runtime_monitor.py",
    "correlator.py",
}


class ProjectMonitor(FileSystemEventHandler):
    def __init__(
        self,
        event_queue: Queue[dict[str, str]],
    ) -> None:
        super().__init__()
        self.event_queue = event_queue
        self.pipeline_active = False

    def should_ignore(
        self,
        path: str | bytes,
    ) -> bool:
        path_string = (
            path.decode()
            if isinstance(path, bytes)
            else path
        )

        resolved_path = Path(path_string).resolve()
        log_folder = LOG_FOLDER.resolve()

        return (
            resolved_path == log_folder
            or log_folder in resolved_path.parents
        )

    def should_trigger_pipeline(
        self,
        path: str | bytes,
    ) -> bool:
        path_string = (
            path.decode()
            if isinstance(path, bytes)
            else path
        )

        source_path = Path(path_string)

        return (
            source_path.suffix.lower()
            in SOURCE_EXTENSIONS
            and source_path.name not in INTERNAL_FILES
        )

    def on_any_event(
        self,
        event: FileSystemEvent,
    ) -> None:
        if event.is_directory:
            return

        if self.pipeline_active:
            return

        if self.should_ignore(event.src_path):
            return

        if not self.should_trigger_pipeline(
            event.src_path
        ):
            return

        src_path = (
            event.src_path.decode()
            if isinstance(
                event.src_path,
                bytes,
            )
            else event.src_path
        )

        event_data: dict[str, str] = {
            "timestamp": datetime.now().isoformat(
                timespec="milliseconds"
            ),
            "type": event.event_type.upper(),
            "path": src_path,
        }

        if event.event_type == "moved":
            destination = (
                event.dest_path.decode()
                if isinstance(
                    event.dest_path,
                    bytes,
                )
                else event.dest_path
            )

            if self.should_ignore(
                event.dest_path
            ):
                return

            if not self.should_trigger_pipeline(
                event.dest_path
            ):
                return

            event_data["destination"] = (
                destination
            )

        self.event_queue.put(
            event_data
        )


def write_event(
    event_data: dict[str, str],
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        LOG_FILE,
        "a",
        encoding="utf-8",
    ) as file:
        file.write(
            json.dumps(event_data)
            + "\n"
        )


def print_event(
    event_data: dict[str, str],
) -> None:
    timestamp = datetime.fromisoformat(
        event_data["timestamp"]
    ).strftime("%H:%M:%S")

    if "destination" in event_data:
        print(
            f"[{timestamp}] "
            f"{event_data['type']:<8} → "
            f"{event_data['path']} → "
            f"{event_data['destination']}"
        )
    else:
        print(
            f"[{timestamp}] "
            f"{event_data['type']:<8} → "
            f"{event_data['path']}"
        )


def get_test_results_signature() -> tuple[int, int] | None:
    try:
        stat = TEST_RESULTS_FILE.stat()
    except FileNotFoundError:
        return None

    return (
        stat.st_size,
        stat.st_mtime_ns,
    )


def get_latest_test_status() -> str | None:
    if not TEST_RESULTS_FILE.exists():
        return None

    try:
        with open(
            TEST_RESULTS_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            lines = file.readlines()

        for line in reversed(lines):
            if not line.strip():
                continue

            result = json.loads(line)
            status = result.get("status")

            if isinstance(status, str):
                return status

    except (
        OSError,
        json.JSONDecodeError,
    ):
        return None

    return None


def run_command(
    script_name: str,
) -> bool:
    script_path = (
        PROJECT_FOLDER / script_name
    )

    print()
    print(
        f"Running {script_name}..."
    )

    result = subprocess.run(
        [
            sys.executable,
            str(script_path),
        ],
        cwd=PROJECT_FOLDER,
        check=False,
    )

    if result.returncode != 0:
        print()
        print(
            f"{script_name} failed "
            f"with exit code "
            f"{result.returncode}."
        )
        return False

    return True


def run_overseer_pipeline() -> None:
    print()
    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - PIPELINE"
    )
    print("=" * 50)

    previous_signature = (
        get_test_results_signature()
    )

    if not run_command(
        "tester.py"
    ):
        print()
        print(
            "Pipeline stopped because "
            "the tester failed."
        )
        return

    current_signature = (
        get_test_results_signature()
    )

    if current_signature == previous_signature:
        print()
        print(
            "Pipeline stopped: no new "
            "test result was recorded."
        )
        return

    test_status = (
        get_latest_test_status()
    )

    if test_status == "PASSED":
        print()
        print(
            "Tests passed. "
            "No diagnosis or changes needed."
        )
        return

    if test_status != "FAILED":
        print()
        print(
            "Pipeline stopped: test status is "
            f"{test_status or 'UNKNOWN'}."
        )
        return

    print()
    print(
        "Tests failed. "
        "Starting diagnosis pipeline."
    )

    pipeline = [
        "project_context.py",
        "evidence_correlator.py",
        "ai_diagnoser.py",
        "permission_manager.py",
        "change_applier.py",
    ]

    for script_name in pipeline:
        if not run_command(
            script_name
        ):
            print()
            print(
                "Pipeline stopped."
            )
            return

    print()
    print("=" * 50)
    print(
        "OVERSEER PIPELINE COMPLETE"
    )
    print("=" * 50)


def get_event_key(
    event_data: dict[str, str],
) -> tuple[str, str]:
    return (
        event_data.get("type", ""),
        event_data.get("path", ""),
    )


def collect_debounced_events(
    first_event: dict[str, str],
    event_queue: Queue[dict[str, str]],
) -> list[dict[str, str]]:
    events = [first_event]

    time.sleep(
        EVENT_DEBOUNCE_SECONDS
    )

    while True:
        try:
            event = event_queue.get_nowait()
        except Empty:
            break

        if (
            get_event_key(event)
            not in {
                get_event_key(existing)
                for existing in events
            }
        ):
            events.append(event)

    return events


def main() -> None:
    event_queue: Queue[
        dict[str, str]
    ] = Queue()

    monitor = ProjectMonitor(
        event_queue
    )

    observer = Observer()

    observer.schedule(
        monitor,
        str(PROJECT_FOLDER),
        recursive=True,
    )

    observer.start()

    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - v0.6"
    )
    print("=" * 50)
    print(
        f"Watching: {PROJECT_FOLDER}"
    )
    print(
        f"Event log: {LOG_FILE}"
    )
    print(
        "Pipeline: ACTIVE"
    )
    print(
        "Press Ctrl+C to stop."
    )
    print()

    last_pipeline_time = 0.0

    try:
        while True:
            try:
                first_event = event_queue.get(
                    timeout=1
                )

                events = (
                    collect_debounced_events(
                        first_event,
                        event_queue,
                    )
                )

                for event_data in events:
                    write_event(
                        event_data
                    )
                    print_event(
                        event_data
                    )

                current_time = (
                    time.monotonic()
                )

                if (
                    current_time
                    - last_pipeline_time
                    < PIPELINE_COOLDOWN_SECONDS
                ):
                    continue

                last_pipeline_time = (
                    current_time
                )

                monitor.pipeline_active = True

                try:
                    run_overseer_pipeline()
                finally:
                    monitor.pipeline_active = False

            except Empty:
                continue

    except KeyboardInterrupt:
        print(
            "\nStopping monitor..."
        )

    finally:
        observer.stop()
        observer.join()

    print(
        "Monitor stopped."
    )


if __name__ == "__main__":
    main()