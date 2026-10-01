from pathlib import Path
import json
from typing import TypedDict


from project_scanner import (
    LANGUAGE_EXTENSIONS,
    PROJECT_FOLDER,
    load_gitignore_patterns,
    normalize_path,
    scan_files,
    should_ignore,
)


LOG_FOLDER = PROJECT_FOLDER / "logs"
CONTEXT_FILE = LOG_FOLDER / "project_context.jsonl"


EXCLUDED_DIRECTORIES = {
    ".git",
    ".pytest_cache",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "target",
    "build",
    "dist",
    "coverage",
}


MAX_FILE_SIZE_BYTES = 1_000_000


class ProjectContextRecord(TypedDict):
    path: str
    language: str
    lines: int
    size_bytes: int
    content: str


def is_excluded_directory(path: Path) -> bool:
    try:
        relative_path = path.relative_to(PROJECT_FOLDER)
    except ValueError:
        return True

    return any(
        part in EXCLUDED_DIRECTORIES
        for part in relative_path.parts
    )


def is_source_file(path: Path) -> bool:
    return path.suffix.lower() in LANGUAGE_EXTENSIONS


def read_source_file(
    path: Path,
) -> str | None:
    try:
        return path.read_text(
            encoding="utf-8"
        )
    except (
        OSError,
        UnicodeDecodeError,
    ):
        return None


def create_context_record(
    path: Path,
    content: str,
) -> ProjectContextRecord:
    language = LANGUAGE_EXTENSIONS.get(
        path.suffix.lower()
    )

    if language is None:
        language = "Unknown"

    return {
        "path": normalize_path(path),
        "language": language,
        "lines": len(content.splitlines()),
        "size_bytes": path.stat().st_size,
        "content": content,
    }


def collect_source_files(
    gitignore_patterns: list[str],
) -> list[Path]:
    source_files: list[Path] = []

    for path in scan_files(
        gitignore_patterns
    ):
        if not path.is_file():
            continue

        if is_excluded_directory(path):
            continue

        if path == CONTEXT_FILE:
            continue

        if not is_source_file(path):
            continue

        try:
            size_bytes = path.stat().st_size
        except OSError:
            continue

        if size_bytes > MAX_FILE_SIZE_BYTES:
            continue

        if should_ignore(
            path,
            gitignore_patterns,
        ):
            continue

        source_files.append(path)

    source_files.sort(
        key=lambda path: normalize_path(path).lower()
    )

    return source_files


def write_context(
    files: list[Path],
) -> int:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    record_count = 0

    with CONTEXT_FILE.open(
        "w",
        encoding="utf-8",
    ) as output_file:
        for path in files:
            content = read_source_file(path)

            if content is None:
                continue

            record = create_context_record(
                path,
                content,
            )

            json.dump(
                record,
                output_file,
                ensure_ascii=False,
            )

            output_file.write("\n")
            record_count += 1

    return record_count


def build_context() -> int:
    gitignore_patterns = (
        load_gitignore_patterns()
    )

    source_files = collect_source_files(
        gitignore_patterns
    )

    return write_context(
        source_files
    )


def main() -> None:
    record_count = build_context()

    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - PROJECT CONTEXT"
    )
    print("=" * 50)
    print()
    print(
        f"Context records: {record_count}"
    )
    print(
        f"Output: {CONTEXT_FILE}"
    )
    print("-" * 50)


if __name__ == "__main__":
    main()