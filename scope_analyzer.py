from __future__ import annotations

from pathlib import Path
from typing import Literal, TypedDict


ScopeStatus = Literal[
    "PASSED",
    "FAILED",
    "INCONCLUSIVE",
]


class ScopeValidationResult(TypedDict):
    expected_files: list[str]
    actual_files: list[str] | None
    unexpected_files: list[str]
    missing_expected_files: list[str]
    scope_status: ScopeStatus
    evidence: list[str]


def canonicalize_scope_path(
    file_path: str,
    project_root: Path,
) -> str | None:
    if not file_path.strip():
        return None

    normalized_input = file_path.replace("\\", "/")
    root = project_root.resolve()
    candidate = Path(normalized_input)

    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved_candidate = candidate.resolve()
        relative_path = resolved_candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None

    if not relative_path.parts:
        return None

    return relative_path.as_posix().casefold()


def normalize_scope_paths(
    file_paths: list[str],
    project_root: Path,
) -> tuple[list[str], bool, bool]:
    normalized_paths: set[str] = set()
    contains_outside_path = False
    contains_invalid_path = False
    root = project_root.resolve()

    for file_path in file_paths:
        canonical_path = canonicalize_scope_path(
            file_path,
            root,
        )

        if canonical_path is not None:
            normalized_paths.add(canonical_path)
            continue

        if not file_path.strip():
            contains_invalid_path = True
            continue

        candidate = Path(file_path.replace("\\", "/"))

        if not candidate.is_absolute():
            candidate = root / candidate

        try:
            candidate.resolve().relative_to(root)
        except (OSError, RuntimeError, ValueError):
            contains_outside_path = True
        else:
            contains_invalid_path = True

    return (
        sorted(normalized_paths),
        contains_outside_path,
        contains_invalid_path,
    )


def compare_scopes(
    expected_files: list[str],
    actual_files: list[str] | None,
    project_root: Path,
) -> ScopeValidationResult:
    normalized_expected, expected_outside, expected_invalid = (
        normalize_scope_paths(expected_files, project_root)
    )
    evidence: list[str] = []

    if expected_outside:
        evidence.append(
            "The approved scope contains a path outside the project root."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": None,
            "unexpected_files": [],
            "missing_expected_files": [],
            "scope_status": "FAILED",
            "evidence": evidence,
        }

    if not normalized_expected:
        evidence.append(
            "The approved affected-file scope is empty or invalid."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": None,
            "unexpected_files": [],
            "missing_expected_files": [],
            "scope_status": "FAILED",
            "evidence": evidence,
        }

    if expected_invalid:
        evidence.append(
            "The approved scope contains a path that cannot be canonicalized."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": None,
            "unexpected_files": [],
            "missing_expected_files": [],
            "scope_status": "INCONCLUSIVE",
            "evidence": evidence,
        }

    if actual_files is None:
        evidence.append(
            "The actual changed-file scope is unavailable."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": None,
            "unexpected_files": [],
            "missing_expected_files": [],
            "scope_status": "INCONCLUSIVE",
            "evidence": evidence,
        }

    normalized_actual, actual_outside, actual_invalid = (
        normalize_scope_paths(actual_files, project_root)
    )
    expected_set = set(normalized_expected)
    actual_set = set(normalized_actual)
    unexpected_files = sorted(actual_set - expected_set)
    missing_expected_files = sorted(expected_set - actual_set)

    if actual_outside:
        evidence.append(
            "The actual change includes a path outside the project root."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": normalized_actual,
            "unexpected_files": unexpected_files,
            "missing_expected_files": missing_expected_files,
            "scope_status": "FAILED",
            "evidence": evidence,
        }

    if actual_invalid:
        evidence.append(
            "The actual changed-file scope contains an invalid path."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": normalized_actual,
            "unexpected_files": unexpected_files,
            "missing_expected_files": missing_expected_files,
            "scope_status": "INCONCLUSIVE",
            "evidence": evidence,
        }

    if unexpected_files:
        evidence.append(
            "The actual change includes files outside the approved scope."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": normalized_actual,
            "unexpected_files": unexpected_files,
            "missing_expected_files": missing_expected_files,
            "scope_status": "FAILED",
            "evidence": evidence,
        }

    if missing_expected_files:
        evidence.append(
            "Some approved affected files were not modified."
        )
        return {
            "expected_files": normalized_expected,
            "actual_files": normalized_actual,
            "unexpected_files": unexpected_files,
            "missing_expected_files": missing_expected_files,
            "scope_status": "INCONCLUSIVE",
            "evidence": evidence,
        }

    evidence.append(
        "The actual changed-file scope exactly matches the approved scope."
    )
    return {
        "expected_files": normalized_expected,
        "actual_files": normalized_actual,
        "unexpected_files": unexpected_files,
        "missing_expected_files": missing_expected_files,
        "scope_status": "PASSED",
        "evidence": evidence,
    }
