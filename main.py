from pathlib import Path
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


WATCH_FOLDER = Path.cwd()


class ProjectMonitor(FileSystemEventHandler):
    def log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {message}")

    def on_created(self, event):
        if not event.is_directory:
            self.log(f"CREATED  → {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory:
            self.log(f"MODIFIED  → {event.src_path}")

    def on_deleted(self, event):
        if not event.is_directory:
            self.log(f"DELETED   → {event.src_path}")

    def on_moved(self, event):
        if not event.is_directory:
            self.log(
                f"MOVED    → {event.src_path} → {event.dest_path}"
            )


def main() -> None:
    monitor = ProjectMonitor()
    observer = Observer()

    observer.schedule(
        monitor,
        str(WATCH_FOLDER),
        recursive=True,
    )

    observer.start()

    print("=" * 50)
    print("AI DEVELOPER OVERSEER - v0.1")
    print("=" * 50)
    print(f"Watching: {WATCH_FOLDER}")
    print("Status: ACTIVE")
    print("Press Ctrl+C to stop.")
    print()

    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("\nStopping monitor...")
        observer.stop()

    observer.join()
    print("Monitor stopped.")


if __name__ == "__main__":
    main()