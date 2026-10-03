from pathlib import Path

import pytest

import scope_analyzer


def test_exact_scope_match_passes(tmp_path: Path) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/module.py"],
        ["src/module.py"],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"
    assert result["expected_files"] == ["src/module.py"]
    assert result["actual_files"] == ["src/module.py"]


def test_multiple_expected_and_actual_files_pass(tmp_path: Path) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/first.py", "src/second.py"],
        ["src/second.py", "src/first.py"],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"


def test_unexpected_actual_file_fails_without_scope_expansion(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/approved.py"],
        ["src/approved.py", "src/unapproved.py"],
        tmp_path,
    )

    assert result["scope_status"] == "FAILED"
    assert result["evidence"] == [
        "The actual change includes files outside the approved scope."
    ]
    assert result["unexpected_files"] == ["src/unapproved.py"]
    assert result["expected_files"] == ["src/approved.py"]


def test_missing_expected_file_is_inconclusive(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/first.py", "src/second.py"],
        ["src/first.py"],
        tmp_path,
    )

    assert result["scope_status"] == "INCONCLUSIVE"
    assert result["missing_expected_files"] == ["src/second.py"]


def test_unknown_actual_scope_is_inconclusive(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/module.py"],
        None,
        tmp_path,
    )

    assert result["scope_status"] == "INCONCLUSIVE"
    assert result["actual_files"] is None


@pytest.mark.parametrize(
    ("expected_files", "actual_files"),
    [
        ([], ["src/module.py"]),
        (["", "   "], ["src/module.py"]),
    ],
)
def test_empty_or_invalid_approved_scope_fails(
    tmp_path: Path,
    expected_files: list[str],
    actual_files: list[str],
) -> None:
    result = scope_analyzer.compare_scopes(
        expected_files,
        actual_files,
        tmp_path,
    )

    assert result["scope_status"] == "FAILED"


def test_duplicate_path_aliases_are_normalized(tmp_path: Path) -> None:
    absolute_path = str(tmp_path / "src" / "module.py")
    result = scope_analyzer.compare_scopes(
        ["src/module.py", absolute_path, "src/./module.py"],
        [absolute_path, "src/module.py"],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"
    assert result["expected_files"] == ["src/module.py"]
    assert result["actual_files"] == ["src/module.py"]


def test_relative_and_absolute_paths_are_equivalent(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["src/module.py"],
        [str(tmp_path / "src" / "module.py")],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"


def test_windows_separators_are_normalized(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["src\\nested\\module.py"],
        ["src/nested/module.py"],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"
    assert result["expected_files"] == ["src/nested/module.py"]


def test_case_differences_are_normalized(
    tmp_path: Path,
) -> None:
    result = scope_analyzer.compare_scopes(
        ["Src/Module.PY"],
        ["src/module.py"],
        tmp_path,
    )

    assert result["scope_status"] == "PASSED"


@pytest.mark.parametrize(
    ("expected_files", "actual_files"),
    [
        (["../outside.py"], ["src/module.py"]),
        (["src/module.py"], ["../outside.py"]),
    ],
)
def test_paths_outside_project_root_are_rejected(
    tmp_path: Path,
    expected_files: list[str],
    actual_files: list[str],
) -> None:
    result = scope_analyzer.compare_scopes(
        expected_files,
        actual_files,
        tmp_path,
    )

    assert result["scope_status"] == "FAILED"
    if expected_files[0] == "../outside.py":
        assert result["evidence"] == [
            "The approved scope contains a path outside the project root."
        ]


def test_applied_scope_cannot_expand_approved_scope(
    tmp_path: Path,
) -> None:
    approved_scope = ["src/approved.py"]

    result = scope_analyzer.compare_scopes(
        approved_scope,
        ["src/approved.py", "src/extra.py"],
        tmp_path,
    )

    assert result["scope_status"] == "FAILED"
    assert result["unexpected_files"] == ["src/extra.py"]
    assert approved_scope == ["src/approved.py"]
