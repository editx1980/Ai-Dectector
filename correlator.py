from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import json
from typing import Any


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
LOG_FILE = LOG_FOLDER / "events.jsonl"
SESSION_LOG_FILE = LOG_FOLDER / "sessions.jsonl"

SESSION_TIMEOUT = 60
DEDUPLICATION_WINDOW = 1


@dataclass
class Event:
    timestamp: datetime
    event_type: str
    path: Path
    destination: Path | None = None


@dataclass
class ChangeSession:
    session_number: int
    started_at: datetime
    ended_at: datetime
    duration_seconds: float
    files: list[str]
    event_types: list[str]
    event_count: int


def load_events() -> list[Event]:
    if not LOG_FILE.exists():
        return []

    events: list[Event] = []

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            raw_event: Any = json.loads(line)

            event = Event(
                timestamp=datetime.fromisoformat(
                    str(raw_event["timestamp"])
                ),
                event_type=str(raw_event["type"]),
                path=Path(str(raw_event["path"])),
                destination=(
                    Path(str(raw_event["destination"]))
                    if "destination" in raw_event
                    else None
                ),
            )

            events.append(event)

    return events


def deduplicate_events(events: list[Event]) -> list[Event]:
    if not events:
        return []

    deduplicated: list[Event] = [events[0]]

    for event in events[1:]:
        previous_event = deduplicated[-1]

        same_type = event.event_type == previous_event.event_type
        same_path = event.path == previous_event.path

        time_difference = (
            event.timestamp - previous_event.timestamp
        ).total_seconds()

        if (
            same_type
            and same_path
            and time_difference <= DEDUPLICATION_WINDOW
        ):
            continue

        deduplicated.append(event)

    return deduplicated


def create_sessions(
    events: list[Event],
) -> list[list[Event]]:
    if not events:
        return []

    sessions: list[list[Event]] = []
    current_session: list[Event] = [events[0]]

    for event in events[1:]:
        previous_event = current_session[-1]

        time_difference = (
            event.timestamp - previous_event.timestamp
        ).total_seconds()

        if time_difference <= SESSION_TIMEOUT:
            current_session.append(event)
        else:
            sessions.append(current_session)
            current_session = [event]

    sessions.append(current_session)

    return sessions


def get_relative_path(path: Path) -> str:
    try:
        return str(path.relative_to(PROJECT_FOLDER))
    except ValueError:
        return str(path)


def build_change_session(
    session_number: int,
    session: list[Event],
) -> ChangeSession:
    start_time = session[0].timestamp
    end_time = session[-1].timestamp

    duration = (
        end_time - start_time
    ).total_seconds()

    files: list[str] = []
    event_types: list[str] = []

    for event in session:
        display_path = get_relative_path(event.path)

        if display_path not in files:
            files.append(display_path)

        if event.event_type not in event_types:
            event_types.append(event.event_type)

        if event.destination is not None:
            display_destination = get_relative_path(
                event.destination
            )

            if display_destination not in files:
                files.append(display_destination)

    return ChangeSession(
        session_number=session_number,
        started_at=start_time,
        ended_at=end_time,
        duration_seconds=duration,
        files=files,
        event_types=event_types,
        event_count=len(session),
    )


def save_sessions(sessions: list[ChangeSession]) -> None:
    LOG_FOLDER.mkdir(parents=True, exist_ok=True)

    with SESSION_LOG_FILE.open("w", encoding="utf-8") as file:
        for session in sessions:
            session_data: dict[str, object] = {
                "session_number": session.session_number,
                "started_at": session.started_at.isoformat(
                    timespec="milliseconds"
                ),
                "ended_at": session.ended_at.isoformat(
                    timespec="milliseconds"
                ),
                "duration_seconds": session.duration_seconds,
                "files": session.files,
                "event_types": session.event_types,
                "event_count": session.event_count,
            }

            file.write(
                json.dumps(session_data)
                + "\n"
            )


def print_session(
    session: ChangeSession,
) -> None:
    print(
        f"CHANGE SESSION #{session.session_number}"
    )
    print(
        f"Started: "
        f"{session.started_at.strftime('%H:%M:%S')}"
    )
    print(
        f"Ended:   "
        f"{session.ended_at.strftime('%H:%M:%S')}"
    )
    print(
        f"Duration: "
        f"{session.duration_seconds:.0f} seconds"
    )
    print()
    print("Files:")

    for file_path in session.files:
        print(f"  {file_path}")

    print()
    print("Event types:")

    for event_type in session.event_types:
        print(f"  {event_type}")

    print()
    print(
        f"Events: {session.event_count}"
    )
    print()
    print("-" * 50)
    print()


def main() -> None:
    print("=" * 50)
    print("AI DEVELOPER OVERSEER - v0.3")
    print("=" * 50)
    print()
    print(f"Analyzing: {LOG_FILE}")
    print(f"Session log: {SESSION_LOG_FILE}")
    print()

    events = load_events()

    if not events:
        print("No events found.")
        return

    deduplicated_events = deduplicate_events(events)
    raw_sessions = create_sessions(deduplicated_events)

    sessions: list[ChangeSession] = []

    for session_number, raw_session in enumerate(
        raw_sessions,
        start=1,
    ):
        sessions.append(
            build_change_session(
                session_number,
                raw_session,
            )
        )

    save_sessions(sessions)

    print(f"Events found: {len(events)}")
    print(
        f"Events after deduplication: "
        f"{len(deduplicated_events)}"
    )
    print(f"Sessions found: {len(sessions)}")
    print()

    for session in sessions:
        print_session(session)


if __name__ == "__main__":
    main()