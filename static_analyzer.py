from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import shutil
import subprocess


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

STATIC_ANALYSIS_FILE = LOG_FOLDER / "static_analysis.jsonl"


def resolve_project_root(
    project_root: str | Path | None = None,
) -> Path:
    if project_root is None:
        return PROJECT_FOLDER

    return Path(project_root).resolve()


@dataclass
class AnalysisFinding:
    tool: str
    language: str
    severity: str
    message: str
    file: str | None
    line: int | None
    column: int | None
    raw_output: str


@dataclass
class AnalysisResult:
    tool: str
    language: str
    available: bool
    exit_code: int | None
    findings: list[AnalysisFinding]


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    command: list[str],
    timeout: int = 30,
    project_root: str | Path | None = None,
) -> tuple[int, str]:
    root = resolve_project_root(project_root)

    try:
        result = subprocess.run(
            command,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )

        output = result.stdout

        if result.stderr:
            output += result.stderr

        return result.returncode, output

    except subprocess.TimeoutExpired as error:
        output = ""

        if error.stdout:
            output += str(error.stdout)

        if error.stderr:
            output += str(error.stderr)

        output += f"\nCommand timed out after {timeout} seconds."

        return -1, output

    except OSError as error:
        return -1, f"Failed to run command: {error}"


def parse_luau_output(
    output: str,
) -> list[AnalysisFinding]:
    findings: list[AnalysisFinding] = []

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        findings.append(
            AnalysisFinding(
                tool="luau-analyze",
                language="Luau",
                severity="ERROR",
                message=stripped,
                file=None,
                line=None,
                column=None,
                raw_output=stripped,
            )
        )

    return findings

def analyze_luau(
    project_root: str | Path | None = None,
) -> AnalysisResult:
    root = resolve_project_root(project_root)

    if not command_exists("luau-analyze"):
        return AnalysisResult(
            tool="luau-analyze",
            language="Luau",
            available=False,
            exit_code=None,
            findings=[],
        )

    luau_files = list(
        root.rglob("*.luau")
    )

    if not luau_files:
        return AnalysisResult(
            tool="luau-analyze",
            language="Luau",
            available=True,
            exit_code=0,
            findings=[],
        )

    command = [
        "luau-analyze",
        *[
            str(path.relative_to(root))
            for path in luau_files
        ],
    ]

    exit_code, output = run_command(command, project_root=root)

    return AnalysisResult(
        tool="luau-analyze",
        language="Luau",
        available=True,
        exit_code=exit_code,
        findings=parse_luau_output(output),
    )


def analyze_python(
    project_root: str | Path | None = None,
) -> AnalysisResult:
    root = resolve_project_root(project_root)
    python_files = list(
        root.rglob("*.py")
    )

    if not python_files:
        return AnalysisResult(
            tool="Python",
            language="Python",
            available=True,
            exit_code=0,
            findings=[],
        )

    findings: list[AnalysisFinding] = []

    for path in python_files:
        relative_path = path.relative_to(root)

        try:
            source = path.read_text(
                encoding="utf-8"
            )

            compile(
                source,
                str(relative_path),
                "exec",
            )

        except SyntaxError as error:
            findings.append(
                AnalysisFinding(
                    tool="Python",
                    language="Python",
                    severity="ERROR",
                    message=error.msg,
                    file=str(relative_path),
                    line=error.lineno,
                    column=error.offset,
                    raw_output=str(error),
                )
            )

        except (OSError, UnicodeError) as error:
            findings.append(
                AnalysisFinding(
                    tool="Python",
                    language="Python",
                    severity="ERROR",
                    message=str(error),
                    file=str(relative_path),
                    line=None,
                    column=None,
                    raw_output=str(error),
                )
            )

    return AnalysisResult(
        tool="Python",
        language="Python",
        available=True,
        exit_code=(
            1
            if findings
            else 0
        ),
        findings=findings,
    )


def analyze_typescript(
    project_root: str | Path | None = None,
) -> AnalysisResult:
    root = resolve_project_root(project_root)

    if not command_exists("tsc"):
        return AnalysisResult(
            tool="tsc",
            language="TypeScript",
            available=False,
            exit_code=None,
            findings=[],
        )

    if not (
        (root / "tsconfig.json").exists()
    ):
        return AnalysisResult(
            tool="tsc",
            language="TypeScript",
            available=True,
            exit_code=0,
            findings=[],
        )

    exit_code, output = run_command(
        [
            "tsc",
            "--noEmit",
        ],
        project_root=root,
    )

    findings: list[AnalysisFinding] = []

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped:
            continue

        findings.append(
            AnalysisFinding(
                tool="tsc",
                language="TypeScript",
                severity="ERROR",
                message=stripped,
                file=None,
                line=None,
                column=None,
                raw_output=stripped,
            )
        )

    return AnalysisResult(
        tool="tsc",
        language="TypeScript",
        available=True,
        exit_code=exit_code,
        findings=findings,
    )


def analyze_javascript(
    project_root: str | Path | None = None,
) -> AnalysisResult:
    root = resolve_project_root(project_root)

    if not command_exists("eslint"):
        return AnalysisResult(
            tool="eslint",
            language="JavaScript",
            available=False,
            exit_code=None,
            findings=[],
        )

    javascript_files = [
        *root.rglob("*.js"),
        *root.rglob("*.jsx"),
    ]

    if not javascript_files:
        return AnalysisResult(
            tool="eslint",
            language="JavaScript",
            available=True,
            exit_code=0,
            findings=[],
        )

    command = [
        "eslint",
        *[
            str(path.relative_to(root))
            for path in javascript_files
        ],
    ]

    exit_code, output = run_command(command, project_root=root)

    findings = [
        AnalysisFinding(
            tool="eslint",
            language="JavaScript",
            severity="WARNING",
            message=line.strip(),
            file=None,
            line=None,
            column=None,
            raw_output=line.strip(),
        )
        for line in output.splitlines()
        if line.strip()
    ]

    return AnalysisResult(
        tool="eslint",
        language="JavaScript",
        available=True,
        exit_code=exit_code,
        findings=findings,
    )


def analyze_project(
    project_root: str | Path | None = None,
) -> list[AnalysisResult]:
    root = resolve_project_root(project_root)
    return [
        analyze_luau(root),
        analyze_python(root),
        analyze_typescript(root),
        analyze_javascript(root),
    ]


def save_results(
    results: list[AnalysisResult],
    project_root: str | Path | None = None,
) -> None:
    root = resolve_project_root(project_root)
    log_folder = root / "logs"
    static_analysis_file = log_folder / "static_analysis.jsonl"

    log_folder.mkdir(
        parents=True,
        exist_ok=True,
    )

    with static_analysis_file.open(
        "w",
        encoding="utf-8",
    ) as file:
        for result in results:
            file.write(
                json.dumps(
                    asdict(result),
                    ensure_ascii=False,
                )
                + "\n"
            )


def print_results(
    results: list[AnalysisResult],
    project_root: str | Path | None = None,
) -> None:
    root = resolve_project_root(project_root)
    static_analysis_file = root / "logs" / "static_analysis.jsonl"
    print()
    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - STATIC ANALYSIS"
    )
    print("=" * 50)

    for result in results:
        print()
        print(f"Tool: {result.tool}")
        print(f"Language: {result.language}")

        if not result.available:
            print("Status: NOT AVAILABLE")
            continue

        print("Status: AVAILABLE")
        print(f"Exit code: {result.exit_code}")
        print(
            f"Findings: {len(result.findings)}"
        )

        for finding in result.findings:
            print(
                f"  [{finding.severity}] "
                f"{finding.message}"
            )

    print()
    print(
        f"Results: {static_analysis_file}"
    )
    print("=" * 50)


def main() -> None:
    import sys

    project_root = (
        Path(sys.argv[1]).resolve()
        if len(sys.argv) > 1
        else PROJECT_FOLDER
    )
    results = analyze_project(project_root)

    save_results(results, project_root)
    print_results(results, project_root)


if __name__ == "__main__":
    main()