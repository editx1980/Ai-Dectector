from __future__ import annotations

import posixpath
from pathlib import PurePosixPath
from typing import Literal, TypedDict, cast

from validation_analyzer import TestFailure, TestResult, TestRunStatus


RiskLevel = Literal["LOW", "MEDIUM", "HIGH", "UNKNOWN"]
EvidenceSource = Literal[
    "DIAGNOSIS_PROVIDED",
    "VERIFIED_TEST_RUN",
    "EXPLICIT_PROJECT_EVIDENCE",
    "UNAVAILABLE",
]
EvidenceState = Literal[
    "PRESENT",
    "ABSENT",
    "UNKNOWN",
    "CONFLICTING",
]


class RiskEvidence(TypedDict):
    factor: str
    source: EvidenceSource
    state: EvidenceState
    detail: str


class ChangeRiskAssessment(TypedDict):
    level: RiskLevel
    reasons: list[str]
    uncertainties: list[str]
    evidence: list[RiskEvidence]
    originating_run_id: str
    test_status: TestRunStatus | None
    test_command: list[str] | None
    relevant_test_failures: list[TestFailure]
    test_result_issue: str | None
    diagnosis_evidence: list[str]
    diagnosis_confidence: str


class ExactEdit(TypedDict):
    file: str | None
    line: int | None
    old_text: str | None
    new_text: str | None


class DiagnosisEvidence(TypedDict):
    confidence: str
    diagnosis: str
    likely_cause: str
    proposed_change: str
    change_size: str
    affected_files: list[str]
    file: str | None
    exact_change: ExactEdit
    evidence: list[str]


class ExplicitProjectEvidence(TypedDict, total=False):
    coverage_complete: bool
    core_infrastructure_files: list[str]
    subsystem_by_file: dict[str, str]


_CONFIGURATION_FILENAMES = {
    "aftman.toml",
    "cargo.lock",
    "cargo.toml",
    "composer.json",
    "composer.lock",
    "default.project.json",
    "gemfile",
    "gemfile.lock",
    "go.mod",
    "go.sum",
    "overseer.json",
    "package-lock.json",
    "package.json",
    "pipfile",
    "pipfile.lock",
    "poetry.lock",
    "pyproject.toml",
    "requirements.in",
    "requirements.txt",
    "rokit.toml",
    "setup.py",
    "tsconfig.json",
    "uv.lock",
    "wally.toml",
}
_CONFIGURATION_SUFFIXES = {
    ".cfg",
    ".conf",
    ".ini",
    ".toml",
    ".yaml",
    ".yml",
}
_TEST_DIRECTORY_NAMES = {"test", "tests", "spec", "specs"}
_KNOWN_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".h",
    ".hpp",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".lua",
    ".luau",
    ".php",
    ".py",
    ".pyi",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}


def normalize_proposed_path(file_path: str) -> str:
    normalized = file_path.replace("\\", "/").strip()
    if not normalized:
        return ""
    return posixpath.normpath(normalized).casefold()


def _is_configuration_or_dependency_path(file_path: str) -> bool:
    path = PurePosixPath(normalize_proposed_path(file_path))
    filename = path.name
    return (
        filename in _CONFIGURATION_FILENAMES
        or filename.startswith("requirements")
        and filename.endswith(".txt")
        or filename.startswith("package")
        and filename.endswith(".json")
        or path.suffix in _CONFIGURATION_SUFFIXES
    )


def _is_test_path(file_path: str) -> bool:
    path = PurePosixPath(normalize_proposed_path(file_path))
    filename = path.name
    return (
        any(part in _TEST_DIRECTORY_NAMES for part in path.parts[:-1])
        or filename.startswith("test_")
        or filename.startswith("test") and filename.endswith(".py")
        or filename.endswith("_test.py")
        or filename.endswith(".test.js")
        or filename.endswith(".test.jsx")
        or filename.endswith(".test.ts")
        or filename.endswith(".test.tsx")
        or filename.endswith(".spec.js")
        or filename.endswith(".spec.jsx")
        or filename.endswith(".spec.ts")
        or filename.endswith(".spec.tsx")
    )


def _make_evidence(
    factor: str,
    source: EvidenceSource,
    state: EvidenceState,
    detail: str,
) -> RiskEvidence:
    return {
        "factor": factor,
        "source": source,
        "state": state,
        "detail": detail,
    }


def _matching_failures(
    failures: list[TestFailure],
    proposed_paths: set[str],
) -> list[TestFailure]:
    return [
        failure
        for failure in failures
        if normalize_proposed_path(failure["file"]) in proposed_paths
    ]


def _assess_project_facts(
    files: list[str],
    project_evidence: ExplicitProjectEvidence | None,
    reasons: list[str],
    uncertainties: list[str],
    evidence: list[RiskEvidence],
) -> tuple[bool, bool, bool]:
    if project_evidence is None or not project_evidence.get(
        "coverage_complete", False
    ):
        uncertainties.append(
            "Core/infrastructure involvement and subsystem boundaries are "
            "not established by explicit project evidence."
        )
        evidence.append(
            _make_evidence(
                "core_and_subsystem_involvement",
                "UNAVAILABLE",
                "UNKNOWN",
                "No complete explicit classification was supplied; no project "
                "scan or stale profile was used.",
            )
        )
        return False, False, False

    normalized_files = {normalize_proposed_path(path) for path in files}
    raw_core_files = project_evidence.get("core_infrastructure_files", [])
    core_files = {
        normalize_proposed_path(path) for path in raw_core_files
    }
    core_matches = sorted(normalized_files & core_files)
    if core_matches:
        reasons.append(
            "Explicit project evidence classifies proposed-scope file(s) as "
            "core/infrastructure: " + ", ".join(core_matches) + "."
        )
        evidence.append(
            _make_evidence(
                "core_infrastructure_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "PRESENT",
                ", ".join(core_matches),
            )
        )
    else:
        evidence.append(
            _make_evidence(
                "core_infrastructure_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "ABSENT",
                "Complete explicit evidence classifies no proposed-scope file "
                "as core/infrastructure.",
            )
        )

    raw_subsystems = project_evidence.get("subsystem_by_file", {})
    normalized_subsystems: dict[str, str] = {}
    conflicting_subsystems: set[str] = set()
    for path, subsystem in raw_subsystems.items():
        normalized_path = normalize_proposed_path(path)
        existing_subsystem = normalized_subsystems.get(normalized_path)
        if existing_subsystem is not None and existing_subsystem != subsystem:
            conflicting_subsystems.add(normalized_path)
        normalized_subsystems[normalized_path] = subsystem
    if normalized_files & conflicting_subsystems:
        conflicts = sorted(normalized_files & conflicting_subsystems)
        uncertainties.append(
            "Explicit subsystem evidence conflicts for proposed-scope file(s): "
            + ", ".join(conflicts)
            + "."
        )
        evidence.append(
            _make_evidence(
                "cross_subsystem_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "CONFLICTING",
                ", ".join(conflicts),
            )
        )
        return bool(core_matches), False, False
    if not normalized_files.issubset(normalized_subsystems):
        uncertainties.append(
            "One or more proposed-scope files lack explicit subsystem "
            "classification; cross-subsystem involvement is unknown."
        )
        evidence.append(
            _make_evidence(
                "cross_subsystem_involvement",
                "UNAVAILABLE",
                "UNKNOWN",
                "Explicit subsystem classifications do not cover every "
                "diagnosis-provided file.",
            )
        )
        return bool(core_matches), False, False

    subsystem_names = {
        normalized_subsystems[file_path]
        for file_path in normalized_files
    }
    if any(not subsystem.strip() for subsystem in subsystem_names):
        uncertainties.append(
            "One or more explicit subsystem classifications are empty; "
            "cross-subsystem involvement is unknown."
        )
        evidence.append(
            _make_evidence(
                "cross_subsystem_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "UNKNOWN",
                "An affected file has an empty subsystem classification.",
            )
        )
        return bool(core_matches), False, False
    if len(subsystem_names) > 1:
        names = ", ".join(sorted(subsystem_names))
        reasons.append(
            "Explicit project evidence places proposed-scope files in "
            f"multiple subsystems: {names}."
        )
        evidence.append(
            _make_evidence(
                "cross_subsystem_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "PRESENT",
                names,
            )
        )
    else:
        evidence.append(
            _make_evidence(
                "cross_subsystem_involvement",
                "EXPLICIT_PROJECT_EVIDENCE",
                "ABSENT",
                "All diagnosis-provided files map to one explicitly identified "
                "subsystem.",
            )
        )
    return bool(core_matches), len(subsystem_names) > 1, True


def analyze_change_risk(
    diagnosis: DiagnosisEvidence,
    originating_run_id: str,
    test_result: TestResult | None,
    project_evidence: ExplicitProjectEvidence | None = None,
    test_result_issue: str | None = None,
) -> ChangeRiskAssessment:
    reasons: list[str] = []
    uncertainties: list[str] = []
    evidence: list[RiskEvidence] = []
    proposed_files = sorted(
        {
            normalize_proposed_path(file_path)
            for file_path in diagnosis["affected_files"]
            if file_path.strip()
        }
    )
    diagnosis_paths_valid = bool(proposed_files) and all(
        PurePosixPath(file_path).suffix
        for file_path in proposed_files
    )

    evidence.append(
        _make_evidence(
            "affected_file_count",
            "DIAGNOSIS_PROVIDED",
            "PRESENT" if proposed_files else "UNKNOWN",
            f"{len(proposed_files)} unique file(s) in diagnosis-provided "
            "proposed scope; not actual changed files.",
        )
    )
    if not proposed_files:
        uncertainties.append(
            "The diagnosis does not provide a usable proposed affected-file "
            "scope."
        )
    elif len(proposed_files) >= 5:
        reasons.append(
            f"The diagnosis-provided proposed scope lists {len(proposed_files)} "
            "unique files; this is not an observed changed-file count."
        )

    extensions = sorted(
        {
            PurePosixPath(file_path).suffix
            for file_path in proposed_files
            if PurePosixPath(file_path).suffix
        }
    )
    if extensions:
        evidence.append(
            _make_evidence(
                "affected_file_types",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "Extensions in proposed scope: " + ", ".join(extensions) + ".",
            )
        )
    else:
        uncertainties.append(
            "Affected file types cannot be derived from the proposed paths."
        )

    unknown_file_types = [
        path
        for path in proposed_files
        if PurePosixPath(path).suffix not in _KNOWN_SOURCE_SUFFIXES
        and not _is_configuration_or_dependency_path(path)
    ]
    if unknown_file_types:
        uncertainties.append(
            "Some diagnosis-provided paths have unclassified file types: "
            + ", ".join(unknown_file_types)
            + "."
        )

    configuration_files = [
        file_path
        for file_path in proposed_files
        if _is_configuration_or_dependency_path(file_path)
    ]
    if configuration_files:
        reasons.append(
            "The diagnosis-provided proposed scope includes recognized "
            "configuration/dependency path(s): "
            + ", ".join(configuration_files)
            + "."
        )
        evidence.append(
            _make_evidence(
                "configuration_or_dependency_involvement",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                ", ".join(configuration_files),
            )
        )
    else:
        evidence.append(
            _make_evidence(
                "configuration_or_dependency_involvement",
                "DIAGNOSIS_PROVIDED",
                "ABSENT",
                "No proposed-scope path matches the analyzer's explicit "
                "configuration/dependency filename rules.",
            )
        )

    test_files = [
        file_path
        for file_path in proposed_files
        if _is_test_path(file_path)
    ]
    if test_files:
        reasons.append(
            "The diagnosis-provided proposed scope includes test file(s): "
            + ", ".join(test_files)
            + "."
        )
        evidence.append(
            _make_evidence(
                "test_file_involvement",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                ", ".join(test_files),
            )
        )
    else:
        evidence.append(
            _make_evidence(
                "test_file_involvement",
                "DIAGNOSIS_PROVIDED",
                "ABSENT",
                "No proposed-scope path matches the analyzer's explicit "
                "test-file naming rules.",
            )
        )

    exact_file = diagnosis["exact_change"]["file"]
    diagnosis_file = diagnosis["file"]
    exact_target_matches_scope = (
        exact_file is not None
        and normalize_proposed_path(exact_file) in proposed_files
    )
    diagnosis_target_matches_scope = (
        diagnosis_file is not None
        and normalize_proposed_path(diagnosis_file) in proposed_files
    )
    scope_conflict = bool(proposed_files) and (
        (
            exact_file is not None
            and not exact_target_matches_scope
        )
        or (
            diagnosis_file is not None
            and not diagnosis_target_matches_scope
        )
    )
    if diagnosis_file is None:
        uncertainties.append(
            "The diagnosis does not identify a diagnosed file for comparison "
            "with its proposed scope."
        )
    if not proposed_files or exact_file is None:
        uncertainties.append(
            "The proposed scope or exact target is unavailable, so scope "
            "consistency cannot be established."
        )
        evidence.append(
            _make_evidence(
                "diagnosis_and_proposed_scope_consistency",
                "DIAGNOSIS_PROVIDED",
                "UNKNOWN",
                "The analyzer cannot compare an unavailable target or scope.",
            )
        )
    elif (
        scope_conflict
    ):
        reasons.append(
            "The diagnosis-provided exact target or diagnosed file conflicts "
            "with the diagnosis-provided proposed scope."
        )
        evidence.append(
            _make_evidence(
                "diagnosis_and_proposed_scope_consistency",
                "DIAGNOSIS_PROVIDED",
                "CONFLICTING",
                "Compared diagnosis.file and diagnosis.exact_change.file with "
                "diagnosis.affected_files.",
            )
        )
    else:
        evidence.append(
            _make_evidence(
                "diagnosis_and_proposed_scope_consistency",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "The diagnosis-provided exact target is included in the "
                "diagnosis-provided proposed scope.",
            )
        )

    change_size = diagnosis["change_size"]
    if change_size == "LARGE":
        reasons.append(
            "The diagnosis labels the proposed change LARGE; this is "
            "diagnosis-reported, not an independently measured diff."
        )
        evidence.append(
            _make_evidence(
                "proposed_change_size",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "change_size=LARGE",
            )
        )
    elif change_size == "MEDIUM":
        reasons.append(
            "The diagnosis labels the proposed change MEDIUM."
        )
        evidence.append(
            _make_evidence(
                "proposed_change_size",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "change_size=MEDIUM",
            )
        )
    elif change_size == "SMALL":
        evidence.append(
            _make_evidence(
                "proposed_change_size",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "change_size=SMALL; diagnosis-reported and not independently "
                "measured.",
            )
        )
    else:
        uncertainties.append(
            "The diagnosis-provided change size is not a supported risk "
            "category."
        )
        evidence.append(
            _make_evidence(
                "proposed_change_size",
                "DIAGNOSIS_PROVIDED",
                "UNKNOWN",
                f"Unsupported or missing value: {change_size!r}.",
            )
        )

    if diagnosis["confidence"] == "LOW":
        uncertainties.append(
            "The diagnosis reports LOW confidence; the proposed cause and "
            "change rationale need careful human review."
        )
        evidence.append(
            _make_evidence(
                "diagnosis_confidence",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "The diagnosis reports LOW confidence.",
            )
        )
    elif diagnosis["confidence"] in {"MEDIUM", "HIGH"}:
        evidence.append(
            _make_evidence(
                "diagnosis_confidence",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                f"The diagnosis reports {diagnosis['confidence']} confidence; "
                "this is not independent verification.",
            )
        )
    else:
        uncertainties.append(
            "The diagnosis confidence is missing or unsupported."
        )
        evidence.append(
            _make_evidence(
                "diagnosis_confidence",
                "DIAGNOSIS_PROVIDED",
                "UNKNOWN",
                f"Unsupported or missing value: {diagnosis['confidence']!r}.",
            )
        )

    if len(proposed_files) in {2, 3, 4}:
        reasons.append(
            f"The diagnosis-provided proposed scope lists {len(proposed_files)} "
            "unique files; this is not an observed changed-file count."
        )

    relevant_failures: list[TestFailure] = []
    test_status: TestRunStatus | None = None
    test_command: list[str] | None = None
    if test_result is None:
        uncertainties.append(
            "No valid test result is available for the diagnosis's originating "
            "run ID."
        )
        evidence.append(
            _make_evidence(
                "originating_test_run",
                "UNAVAILABLE",
                "UNKNOWN",
                test_result_issue
                or f"No validated result found for run_id={originating_run_id}.",
            )
        )
    elif test_result["run_id"] != originating_run_id:
        uncertainties.append(
            "The supplied test result run ID conflicts with the originating "
            "diagnosis run ID."
        )
        evidence.append(
            _make_evidence(
                "originating_test_run",
                "VERIFIED_TEST_RUN",
                "CONFLICTING",
                f"Expected run_id={originating_run_id}; received "
                f"run_id={test_result['run_id']}.",
            )
        )
    else:
        test_status = test_result["status"]
        test_command = list(test_result["command"])
        relevant_failures = _matching_failures(
            test_result["failures"],
            set(proposed_files),
        )
        evidence.append(
            _make_evidence(
                "originating_test_run",
                "VERIFIED_TEST_RUN",
                "PRESENT",
                f"status={test_status}; run_id={originating_run_id}; command="
                f"{' '.join(test_command)}.",
            )
        )
        if test_status != "FAILED":
            uncertainties.append(
                "The originating run does not record FAILED status, so its "
                "relevance as pre-change failure evidence is uncertain."
            )
        if test_status != "FAILED" and test_result["failures"]:
            uncertainties.append(
                "The test result status conflicts with its recorded failure "
                "entries."
            )
            evidence.append(
                _make_evidence(
                    "originating_test_run_consistency",
                    "VERIFIED_TEST_RUN",
                    "CONFLICTING",
                    "A non-FAILED run contains failure records.",
                )
            )
        if relevant_failures:
            evidence.append(
                _make_evidence(
                    "relevant_test_failure",
                    "VERIFIED_TEST_RUN",
                    "PRESENT",
                    f"{len(relevant_failures)} recorded failure(s) in "
                    "diagnosis-provided proposed scope.",
                )
            )
        else:
            uncertainties.append(
                "The originating test result has no failure record matching "
                "the diagnosis-provided proposed scope; test relevance is "
                "unestablished."
            )
            evidence.append(
                _make_evidence(
                    "relevant_test_failure",
                    "VERIFIED_TEST_RUN",
                    "UNKNOWN",
                    "No matching failure could be confirmed from this run's "
                    "failure records.",
                )
            )

    diagnosis_statements = diagnosis["evidence"]
    if diagnosis_statements:
        evidence.append(
            _make_evidence(
                "diagnosis_evidence",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "Diagnosis-provided evidence statements are preserved in the "
                "assessment; they are not independently verified by this "
                "analyzer.",
            )
        )
        evidence.extend(
            _make_evidence(
                f"diagnosis_evidence_{index}",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                statement,
            )
            for index, statement in enumerate(diagnosis_statements, start=1)
        )
    else:
        uncertainties.append(
            "The diagnosis provides no supporting evidence statements."
        )
        evidence.append(
            _make_evidence(
                "diagnosis_evidence",
                "DIAGNOSIS_PROVIDED",
                "UNKNOWN",
                "No diagnosis-provided evidence statements were recorded.",
            )
        )
    rationale_fields = (
        diagnosis["diagnosis"],
        diagnosis["likely_cause"],
        diagnosis["proposed_change"],
    )
    if all(value.strip() for value in rationale_fields) and diagnosis_statements:
        evidence.append(
            _make_evidence(
                "proposal_diagnosis_link",
                "DIAGNOSIS_PROVIDED",
                "PRESENT",
                "The diagnosis, likely cause, proposed change, and evidence are "
                "linked in the diagnosis record; this analyzer does not "
                "independently establish that the change resolves the cause.",
            )
        )
        uncertainties.append(
            "The causal link between the proposed change and diagnosed cause "
            "remains diagnosis-reported; it is not independently proven before "
            "applying the change."
        )
    else:
        uncertainties.append(
            "The diagnosis does not provide enough linked problem, cause, "
            "proposed-change, and evidence text to explain its rationale."
        )
        evidence.append(
            _make_evidence(
                "proposal_diagnosis_link",
                "DIAGNOSIS_PROVIDED",
                "UNKNOWN",
                "One or more diagnosis/rationale fields are empty.",
            )
        )

    core_involved, cross_subsystem, project_classification_complete = (
        _assess_project_facts(
            proposed_files,
            project_evidence,
            reasons,
            uncertainties,
            evidence,
        )
    )
    if core_involved:
        reasons.append(
            "Explicit project evidence identifies core/infrastructure "
            "involvement."
        )
    if cross_subsystem:
        reasons.append(
            "Explicit project evidence identifies a cross-subsystem proposed "
            "change."
        )

    evidence.append(
        _make_evidence(
            "changed_line_count",
            "UNAVAILABLE",
            "UNKNOWN",
            "No whole-project or applied diff exists before permission; exact "
            "edit text is not used to claim a line count.",
        )
    )
    uncertainties.append(
        "Whole-change line count and actual changed-file scope are unavailable "
        "before application; exact edit text is not treated as a project diff."
    )

    high_signal = (
        len(proposed_files) >= 5
        or bool(configuration_files)
        or change_size == "LARGE"
        or scope_conflict
        or core_involved
        or cross_subsystem
    )
    medium_signal = (
        len(proposed_files) in {2, 3, 4}
        or bool(test_files)
        or change_size == "MEDIUM"
    )

    if high_signal:
        level: RiskLevel = "HIGH"
    elif medium_signal:
        level = "MEDIUM"
    elif (
        len(proposed_files) == 1
        and diagnosis_paths_valid
        and change_size == "SMALL"
        and exact_target_matches_scope
        and diagnosis_target_matches_scope
        and test_result is not None
        and test_result["run_id"] == originating_run_id
        and test_status == "FAILED"
        and bool(relevant_failures)
        and project_classification_complete
        and bool(diagnosis["evidence"])
        and not unknown_file_types
        and diagnosis["confidence"] in {"MEDIUM", "HIGH"}
    ):
        level = "LOW"
    else:
        level = "UNKNOWN"

    if level == "UNKNOWN":
        reasons.append(
            "Available evidence is insufficient to classify this proposal "
            "reliably; unknown factors are not treated as low risk."
        )

    return {
        "level": level,
        "reasons": reasons,
        "uncertainties": list(dict.fromkeys(uncertainties)),
        "evidence": evidence,
        "originating_run_id": originating_run_id,
        "test_status": test_status,
        "test_command": test_command,
        "relevant_test_failures": relevant_failures,
        "test_result_issue": test_result_issue,
        "diagnosis_evidence": list(diagnosis_statements),
        "diagnosis_confidence": diagnosis["confidence"],
    }


def parse_change_risk_assessment(
    value: object,
) -> ChangeRiskAssessment | None:
    if not isinstance(value, dict):
        return None
    record = cast(dict[object, object], value)
    level = record.get("level")
    reasons = record.get("reasons")
    uncertainties = record.get("uncertainties")
    raw_evidence = record.get("evidence")
    originating_run_id = record.get("originating_run_id")
    test_status = record.get("test_status")
    test_command = record.get("test_command")
    raw_failures = record.get("relevant_test_failures")
    test_result_issue = record.get("test_result_issue")
    diagnosis_evidence = record.get("diagnosis_evidence")
    diagnosis_confidence = record.get("diagnosis_confidence")

    if level not in {"LOW", "MEDIUM", "HIGH", "UNKNOWN"}:
        return None
    if not isinstance(reasons, list) or not all(
        isinstance(item, str) for item in cast(list[object], reasons)
    ):
        return None
    if not isinstance(uncertainties, list) or not all(
        isinstance(item, str) for item in cast(list[object], uncertainties)
    ):
        return None
    if not isinstance(diagnosis_evidence, list) or not all(
        isinstance(item, str)
        for item in cast(list[object], diagnosis_evidence)
    ):
        return None
    if not isinstance(diagnosis_confidence, str):
        return None
    if not isinstance(raw_evidence, list):
        return None
    evidence: list[RiskEvidence] = []
    for raw_item in cast(list[object], raw_evidence):
        if not isinstance(raw_item, dict):
            return None
        item = cast(dict[object, object], raw_item)
        factor = item.get("factor")
        source = item.get("source")
        state = item.get("state")
        detail = item.get("detail")
        if (
            not isinstance(factor, str)
            or source
            not in {
                "DIAGNOSIS_PROVIDED",
                "VERIFIED_TEST_RUN",
                "EXPLICIT_PROJECT_EVIDENCE",
                "UNAVAILABLE",
            }
            or state
            not in {"PRESENT", "ABSENT", "UNKNOWN", "CONFLICTING"}
            or not isinstance(detail, str)
        ):
            return None
        evidence.append(
            {
                "factor": factor,
                "source": cast(EvidenceSource, source),
                "state": cast(EvidenceState, state),
                "detail": detail,
            }
        )
    if not isinstance(originating_run_id, str) or not originating_run_id:
        return None
    if test_status is not None and test_status not in {
        "PASSED",
        "FAILED",
        "NO_TESTS",
    }:
        return None
    if test_result_issue is not None and not isinstance(
        test_result_issue, str
    ):
        return None
    if test_command is not None and (
        not isinstance(test_command, list)
        or not all(
            isinstance(item, str) for item in cast(list[object], test_command)
        )
    ):
        return None
    if not isinstance(raw_failures, list):
        return None
    relevant_failures: list[TestFailure] = []
    for raw_failure in cast(list[object], raw_failures):
        if not isinstance(raw_failure, dict):
            return None
        failure = cast(dict[object, object], raw_failure)
        file_path = failure.get("file")
        line = failure.get("line")
        test_name = failure.get("test")
        if (
            not isinstance(file_path, str)
            or not isinstance(line, int)
            or isinstance(line, bool)
            or (test_name is not None and not isinstance(test_name, str))
        ):
            return None
        parsed_failure: TestFailure = {"file": file_path, "line": line}
        if isinstance(test_name, str):
            parsed_failure["test"] = test_name
        relevant_failures.append(parsed_failure)

    return {
        "level": cast(RiskLevel, level),
        "reasons": cast(list[str], reasons),
        "uncertainties": cast(list[str], uncertainties),
        "evidence": evidence,
        "originating_run_id": originating_run_id,
        "test_status": cast(TestRunStatus | None, test_status),
        "test_command": (
            cast(list[str], test_command)
            if isinstance(test_command, list)
            else None
        ),
        "relevant_test_failures": relevant_failures,
        "test_result_issue": test_result_issue,
        "diagnosis_evidence": cast(list[str], diagnosis_evidence),
        "diagnosis_confidence": diagnosis_confidence,
    }
