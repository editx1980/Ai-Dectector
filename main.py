from pathlib import Path
from datetime import datetime
from queue import Queue, Empty
import json

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
LOG_FILE = LOG_FOLDER / "events.jsonl"


class ProjectMonitor(FileSystemEventHandler):
    def __init__(self, event_queue: Queue[dict[str, str]]) -> None:
        super().__init__()
        self.event_queue = event_queue

    def should_ignore(self, path: str | bytes) -> bool:
        path_string = path.decode() if isinstance(path, bytes) else path
        resolved_path = Path(path_string).resolve()
        log_folder = LOG_FOLDER.resolve()

        return (
            resolved_path == log_folder
            or log_folder in resolved_path.parents
        )

    def on_any_event(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return

        if self.should_ignore(event.src_path):
            return

        src_path = (
            event.src_path.decode()
            if isinstance(event.src_path, bytes)
            else event.src_path
        )

        event_data: dict[str, str] = {
            "timestamp": datetime.now().isoformat(timespec="milliseconds"),
            "type": event.event_type.upper(),
            "path": src_path,
        }

        if event.event_type == "moved":
            destination = (
                event.dest_path.decode()
                if isinstance(event.dest_path, bytes)
                else event.dest_path
            )

            if self.should_ignore(event.dest_path):
                return

            event_data["destination"] = destination

        self.event_queue.put(event_data)


def write_event(event_data: dict[str, str]) -> None:
    LOG_FOLDER.mkdir(parents=True, exist_ok=True)

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(json.dumps(event_data) + "\n")


def print_event(event_data: dict[str, str]) -> None:
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


def main() -> None:
    event_queue: Queue[dict[str, str]] = Queue()

    monitor = ProjectMonitor(event_queue)
    observer = Observer()

    observer.schedule(
        monitor,
        str(PROJECT_FOLDER),
        recursive=True,
    )

    observer.start()

    print("=" * 50)
    print("AI DEVELOPER OVERSEER - v0.2")
    print("=" * 50)
    print(f"Watching: {PROJECT_FOLDER}")
    print(f"Event log: {LOG_FILE}")
    print("Status: ACTIVE")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            try:
                event_data = event_queue.get(timeout=1)

                write_event(event_data)
                print_event(event_data)

            except Empty:
                continue

    except KeyboardInterrupt:
        print("\nStopping monitor...")

    finally:
        observer.stop()
        observer.join()

    print("Monitor stopped.")


if __name__ == "__main__":
    main()