from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import shutil
import subprocess


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"

STATIC_ANALYSIS_FILE = LOG_FOLDER / "static_analysis.jsonl"


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
) -> tuple[int, str]:
    try:
        result = subprocess.run(
            command,
            cwd=PROJECT_FOLDER,
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

def analyze_luau() -> AnalysisResult:
    if not command_exists("luau-analyze"):
        return AnalysisResult(
            tool="luau-analyze",
            language="Luau",
            available=False,
            exit_code=None,
            findings=[],
        )

    luau_files = list(
        PROJECT_FOLDER.rglob("*.luau")
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
            str(path.relative_to(PROJECT_FOLDER))
            for path in luau_files
        ],
    ]

    exit_code, output = run_command(command)

    return AnalysisResult(
        tool="luau-analyze",
        language="Luau",
        available=True,
        exit_code=exit_code,
        findings=parse_luau_output(output),
    )


def analyze_python() -> AnalysisResult:
    python_files = list(
        PROJECT_FOLDER.rglob("*.py")
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
        relative_path = path.relative_to(
            PROJECT_FOLDER
        )

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


def analyze_typescript() -> AnalysisResult:
    if not command_exists("tsc"):
        return AnalysisResult(
            tool="tsc",
            language="TypeScript",
            available=False,
            exit_code=None,
            findings=[],
        )

    if not (
        (PROJECT_FOLDER / "tsconfig.json").exists()
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
        ]
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


def analyze_javascript() -> AnalysisResult:
    if not command_exists("eslint"):
        return AnalysisResult(
            tool="eslint",
            language="JavaScript",
            available=False,
            exit_code=None,
            findings=[],
        )

    javascript_files = [
        *PROJECT_FOLDER.rglob("*.js"),
        *PROJECT_FOLDER.rglob("*.jsx"),
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
            str(path.relative_to(PROJECT_FOLDER))
            for path in javascript_files
        ],
    ]

    exit_code, output = run_command(command)

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


def analyze_project() -> list[AnalysisResult]:
    return [
        analyze_luau(),
        analyze_python(),
        analyze_typescript(),
        analyze_javascript(),
    ]


def save_results(
    results: list[AnalysisResult],
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    with STATIC_ANALYSIS_FILE.open(
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
) -> None:
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
        f"Results: {STATIC_ANALYSIS_FILE}"
    )
    print("=" * 50)


def main() -> None:
    results = analyze_project()

    save_results(results)
    print_results(results)


if __name__ == "__main__":
    main()