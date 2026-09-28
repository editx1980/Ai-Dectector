from pathlib import Path
from datetime import datetime
import json


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
LOG_FILE = LOG_FOLDER / "events.jsonl"

SESSION_TIMEOUT = 60


def load_events() -> list[dict[str, str]]:
    if not LOG_FILE.exists():
        return []

    events: list[dict[str, str]] = []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            event = json.loads(line)
            events.append(event)

    return events


def create_sessions(
    events: list[dict[str, str]],
) -> list[list[dict[str, str]]]:
    if not events:
        return []

    sessions: list[list[dict[str, str]]] = []
    current_session: list[dict[str, str]] = [events[0]]

    for event in events[1:]:
        previous_event = current_session[-1]

        previous_time = datetime.fromisoformat(
            previous_event["timestamp"]
        )
        current_time = datetime.fromisoformat(
            event["timestamp"]
        )

        difference = (
            current_time - previous_time
        ).total_seconds()

        if difference <= SESSION_TIMEOUT:
            current_session.append(event)
        else:
            sessions.append(current_session)
            current_session = [event]

    sessions.append(current_session)

    return sessions


def print_session(
    session_number: int,
    session: list[dict[str, str]],
) -> None:
    start_time = datetime.fromisoformat(
        session[0]["timestamp"]
    )
    end_time = datetime.fromisoformat(
        session[-1]["timestamp"]
    )

    duration = (
        end_time - start_time
    ).total_seconds()

    files: list[str] = []

    for event in session:
        path = event["path"]

        if path not in files:
            files.append(path)

        if "destination" in event:
            destination = event["destination"]

            if destination not in files:
                files.append(destination)

    print(f"CHANGE SESSION #{session_number}")
    print(f"Started: {start_time.strftime('%H:%M:%S')}")
    print(f"Ended:   {end_time.strftime('%H:%M:%S')}")
    print(f"Duration: {duration:.0f} seconds")
    print()
    print("Files:")

    for file in files:
        print(f"  {file}")

    print()
    print(f"Events: {len(session)}")
    print()
    print("-" * 50)
    print()


def main() -> None:
    print("=" * 50)
    print("AI DEVELOPER OVERSEER - v0.3")
    print("=" * 50)
    print()
    print(f"Analyzing: {LOG_FILE}")
    print()

    events = load_events()

    if not events:
        print("No events found.")
        return

    sessions = create_sessions(events)

    print(f"Events found: {len(events)}")
    print(f"Sessions found: {len(sessions)}")
    print()

    for session_number, session in enumerate(sessions, start=1):
        print_session(session_number, session)


if __name__ == "__main__":
    main()