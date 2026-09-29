from dataclasses import asdict, dataclass
from pathlib import Path
import fnmatch
import json
import tomllib


PROJECT_FOLDER = Path(__file__).resolve().parent
LOG_FOLDER = PROJECT_FOLDER / "logs"
PROFILE_FILE = LOG_FOLDER / "project_profile.json"
GITIGNORE_FILE = PROJECT_FOLDER / ".gitignore"


LANGUAGE_EXTENSIONS = {
    ".py": "Python",
    ".luau": "Luau",
    ".lua": "Lua",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".cpp": "C++",
    ".cc": "C++",
    ".cxx": "C++",
    ".h": "C/C++",
    ".hpp": "C++",
    ".cs": "C#",
    ".rs": "Rust",
    ".java": "Java",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".swift": "Swift",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
}


PROJECT_MARKERS = {
    "default.project.json": ("tool", "Rojo"),
    "wally.toml": ("package_manager", "Wally"),
    "rokit.toml": ("tool", "Rokit"),
    "aftman.toml": ("tool", "Aftman"),
    "pyproject.toml": ("project_file", "Python project"),
    "requirements.txt": ("package_manager", "pip"),
    "package.json": ("project_file", "Node.js"),
    "Cargo.toml": ("project_file", "Rust"),
    "go.mod": ("project_file", "Go"),
    "*.csproj": ("project_file", ".NET"),
    "*.sln": ("project_file", ".NET Solution"),
}


@dataclass
class LanguageInfo:
    name: str
    files: int
    percentage: float


@dataclass
class DependencyInfo:
    name: str
    source: str


@dataclass
class TestStrategy:
    framework: str
    command: list[str]
    source: str


@dataclass
class ProjectProfile:
    path: str
    total_files: int
    languages: list[LanguageInfo]
    primary_language: str | None
    project_type: str | None
    tools: list[str]
    package_managers: list[str]
    project_files: list[str]
    dependencies: list[DependencyInfo]
    configuration_files: list[str]
    directories: list[str]
    test_strategies: list[TestStrategy]


def load_gitignore_patterns() -> list[str]:
    if not GITIGNORE_FILE.exists():
        return []

    try:
        with GITIGNORE_FILE.open("r", encoding="utf-8") as file:
            patterns: list[str] = []

            for line in file:
                pattern = line.strip()

                if not pattern:
                    continue

                if pattern.startswith("#"):
                    continue

                patterns.append(pattern)

            return patterns

    except OSError:
        return []


def normalize_path(path: Path) -> str:
    relative_path = path.relative_to(PROJECT_FOLDER)

    return str(relative_path).replace("\\", "/")


def matches_gitignore_pattern(
    path: Path,
    pattern: str,
) -> bool:
    relative_path = normalize_path(path)

    is_directory_pattern = pattern.endswith("/")

    if is_directory_pattern:
        pattern = pattern.rstrip("/")

        if not pattern:
            return False

        path_parts = relative_path.split("/")

        return any(
            fnmatch.fnmatch(part, pattern)
            for part in path_parts
        )

    if "/" in pattern:
        return fnmatch.fnmatch(
            relative_path,
            pattern,
        )

    return any(
        fnmatch.fnmatch(part, pattern)
        for part in relative_path.split("/")
    )


def should_ignore(
    path: Path,
    patterns: list[str],
) -> bool:
    try:
        relative_path = path.relative_to(PROJECT_FOLDER)

    except ValueError:
        return True

    if not relative_path.parts:
        return False

    if ".git" in relative_path.parts:
        return True

    ignored = False

    for pattern in patterns:
        is_negated = pattern.startswith("!")

        if is_negated:
            pattern = pattern[1:]

        if not pattern:
            continue

        if matches_gitignore_pattern(path, pattern):
            ignored = not is_negated

    return ignored


def scan_files(
    gitignore_patterns: list[str],
) -> list[Path]:
    files: list[Path] = []

    for path in PROJECT_FOLDER.rglob("*"):
        if not path.is_file():
            continue

        if should_ignore(path, gitignore_patterns):
            continue

        files.append(path)

    return files


def detect_languages(
    files: list[Path],
) -> list[LanguageInfo]:
    counts: dict[str, int] = {}

    for path in files:
        language = LANGUAGE_EXTENSIONS.get(
            path.suffix.lower()
        )

        if language is None:
            continue

        counts[language] = counts.get(language, 0) + 1

    total = sum(counts.values())

    if total == 0:
        return []

    languages = [
        LanguageInfo(
            name=name,
            files=count,
            percentage=round(
                count / total * 100,
                1,
            ),
        )
        for name, count in counts.items()
    ]

    languages.sort(
        key=lambda language: language.files,
        reverse=True,
    )

    return languages


def detect_project_type(
    languages: list[LanguageInfo],
) -> str | None:
    if not languages:
        return None

    primary = languages[0].name

    project_types = {
        "Python": "Python project",
        "Luau": "Roblox/Luau project",
        "Lua": "Lua project",
        "JavaScript": "JavaScript project",
        "TypeScript": "TypeScript project",
        "C++": "C++ project",
        "C/C++": "C/C++ project",
        "C#": ".NET project",
        "Rust": "Rust project",
        "Java": "Java project",
        "Go": "Go project",
        "Ruby": "Ruby project",
        "PHP": "PHP project",
        "Swift": "Swift project",
        "Kotlin": "Kotlin project",
    }

    return project_types.get(
        primary,
        f"{primary} project",
    )


def detect_project_markers(
    files: list[Path],
) -> tuple[
    list[str],
    list[str],
    list[str],
]:
    tools: list[str] = []
    package_managers: list[str] = []
    project_files: list[str] = []

    filenames = {
        path.name
        for path in files
    }

    for marker, result in PROJECT_MARKERS.items():
        category, name = result

        if "*" in marker:
            if any(
                fnmatch.fnmatch(
                    filename,
                    marker,
                )
                for filename in filenames
            ):
                if category == "tool":
                    tools.append(name)
                elif category == "package_manager":
                    package_managers.append(name)
                else:
                    project_files.append(name)

        elif marker in filenames:
            if category == "tool":
                tools.append(name)
            elif category == "package_manager":
                package_managers.append(name)
            else:
                project_files.append(name)

    return (
        tools,
        package_managers,
        project_files,
    )


def detect_dependencies(
    files: list[Path],
) -> list[DependencyInfo]:
    dependencies: list[DependencyInfo] = []

    requirements_file = next(
        (
            path
            for path in files
            if path.name == "requirements.txt"
        ),
        None,
    )

    if requirements_file is not None:
        try:
            content = requirements_file.read_text(
                encoding="utf-8"
            )

            for line in content.splitlines():
                dependency = line.strip()

                if not dependency:
                    continue

                if dependency.startswith("#"):
                    continue

                dependencies.append(
                    DependencyInfo(
                        name=dependency,
                        source="requirements.txt",
                    )
                )

        except OSError:
            pass

    package_file = next(
        (
            path
            for path in files
            if path.name == "package.json"
        ),
        None,
    )

    if package_file is not None:
        try:
            data = json.loads(
                package_file.read_text(
                    encoding="utf-8"
                )
            )

            if isinstance(data, dict):
                raw_dependencies = data.get(
                    "dependencies"
                )

                if isinstance(
                    raw_dependencies,
                    dict,
                ):
                    for name in raw_dependencies:
                        dependencies.append(
                            DependencyInfo(
                                name=name,
                                source="package.json",
                            )
                        )

        except (
            OSError,
            json.JSONDecodeError,
        ):
            pass

    pyproject_file = next(
        (
            path
            for path in files
            if path.name == "pyproject.toml"
        ),
        None,
    )

    if pyproject_file is not None:
        try:
            with pyproject_file.open(
                "rb"
            ) as file:
                data = tomllib.load(file)

            project = data.get("project")

            if isinstance(project, dict):
                raw_dependencies = project.get(
                    "dependencies"
                )

                if isinstance(
                    raw_dependencies,
                    list,
                ):
                    for dependency in raw_dependencies:
                        if isinstance(
                            dependency,
                            str,
                        ):
                            dependencies.append(
                                DependencyInfo(
                                    name=dependency,
                                    source="pyproject.toml",
                                )
                            )

        except (
            OSError,
            tomllib.TOMLDecodeError,
        ):
            pass

    return dependencies


def detect_configuration_files(
    files: list[Path],
) -> list[str]:
    known_files = {
        "overseer.json",
        "pyproject.toml",
        "requirements.txt",
        "package.json",
        "tsconfig.json",
        "default.project.json",
        "wally.toml",
        "rokit.toml",
        "aftman.toml",
        "Cargo.toml",
        "go.mod",
    }

    return sorted(
        path.name
        for path in files
        if path.name in known_files
    )


def detect_directories(
    gitignore_patterns: list[str],
) -> list[str]:
    directories: list[str] = []

    for path in PROJECT_FOLDER.rglob("*"):
        if not path.is_dir():
            continue

        if should_ignore(
            path,
            gitignore_patterns,
        ):
            continue

        try:
            relative_path = path.relative_to(
                PROJECT_FOLDER
            )
        except ValueError:
            continue

        if not relative_path.parts:
            continue

        directories.append(
            str(relative_path).replace(
                "\\",
                "/",
            )
        )

    return sorted(directories)


def detect_python_test_strategies(
    files: list[Path],
) -> list[TestStrategy]:
    strategies: list[TestStrategy] = []

    requirements_file = next(
        (
            path
            for path in files
            if path.name == "requirements.txt"
        ),
        None,
    )

    if requirements_file is not None:
        try:
            content = requirements_file.read_text(
                encoding="utf-8"
            ).lower()

            if "pytest" in content:
                strategies.append(
                    TestStrategy(
                        framework="pytest",
                        command=[
                            "python",
                            "-m",
                            "pytest",
                        ],
                        source="requirements.txt",
                    )
                )

        except OSError:
            pass

    pyproject_file = next(
        (
            path
            for path in files
            if path.name == "pyproject.toml"
        ),
        None,
    )

    if pyproject_file is not None:
        try:
            with pyproject_file.open(
                "rb"
            ) as file:
                data = tomllib.load(file)

            if "pytest" in str(data).lower():
                strategies.append(
                    TestStrategy(
                        framework="pytest",
                        command=[
                            "python",
                            "-m",
                            "pytest",
                        ],
                        source="pyproject.toml",
                    )
                )

        except (
            OSError,
            tomllib.TOMLDecodeError,
        ):
            pass

    has_python_tests = any(
        (
            path.name.startswith("test_")
            and path.suffix == ".py"
        )
        or path.name.endswith("_test.py")
        for path in files
    )

    if (
        has_python_tests
        and not any(
            strategy.framework == "pytest"
            for strategy in strategies
        )
    ):
        strategies.append(
            TestStrategy(
                framework="pytest",
                command=[
                    "python",
                    "-m",
                    "pytest",
                ],
                source="Python test files",
            )
        )

    return strategies


def detect_node_test_strategies() -> list[TestStrategy]:
    package_file = PROJECT_FOLDER / "package.json"

    if not package_file.exists():
        return []

    try:
        data = json.loads(
            package_file.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(data, dict):
            return []

        scripts = data.get("scripts")

        if not isinstance(scripts, dict):
            return []

        test_script = scripts.get("test")

        if isinstance(test_script, str):
            return [
                TestStrategy(
                    framework="package.json test script",
                    command=[
                        "npm",
                        "test",
                    ],
                    source="package.json",
                )
            ]

    except (
        OSError,
        json.JSONDecodeError,
    ):
        pass

    return []


def detect_other_test_strategies(
    files: list[Path],
) -> list[TestStrategy]:
    strategies: list[TestStrategy] = []

    if (PROJECT_FOLDER / "Cargo.toml").exists():
        strategies.append(
            TestStrategy(
                framework="Cargo test",
                command=[
                    "cargo",
                    "test",
                ],
                source="Cargo.toml",
            )
        )

    if (PROJECT_FOLDER / "go.mod").exists():
        strategies.append(
            TestStrategy(
                framework="Go test",
                command=[
                    "go",
                    "test",
                    "./...",
                ],
                source="go.mod",
            )
        )

    if any(
        path.suffix == ".csproj"
        for path in files
    ):
        strategies.append(
            TestStrategy(
                framework=".NET test",
                command=[
                    "dotnet",
                    "test",
                ],
                source=".csproj",
            )
        )

    if any(
        path.suffix == ".sln"
        for path in files
    ):
        if not any(
            strategy.framework == ".NET test"
            for strategy in strategies
        ):
            strategies.append(
                TestStrategy(
                    framework=".NET test",
                    command=[
                        "dotnet",
                        "test",
                    ],
                    source=".sln",
                )
            )

    return strategies


def detect_test_strategies(
    files: list[Path],
) -> list[TestStrategy]:
    strategies: list[TestStrategy] = []

    strategies.extend(
        detect_python_test_strategies(files)
    )

    strategies.extend(
        detect_node_test_strategies()
    )

    strategies.extend(
        detect_other_test_strategies(files)
    )

    unique: dict[
        str,
        TestStrategy,
    ] = {}

    for strategy in strategies:
        key = " ".join(strategy.command)

        if key not in unique:
            unique[key] = strategy

    return list(unique.values())


def scan_project() -> ProjectProfile:
    gitignore_patterns = load_gitignore_patterns()

    files = scan_files(
        gitignore_patterns
    )

    languages = detect_languages(files)

    (
        tools,
        package_managers,
        project_files,
    ) = detect_project_markers(files)

    return ProjectProfile(
        path=str(PROJECT_FOLDER),
        total_files=len(files),
        languages=languages,
        primary_language=(
            languages[0].name
            if languages
            else None
        ),
        project_type=detect_project_type(
            languages
        ),
        tools=tools,
        package_managers=package_managers,
        project_files=project_files,
        dependencies=detect_dependencies(files),
        configuration_files=(
            detect_configuration_files(files)
        ),
        directories=detect_directories(
            gitignore_patterns
        ),
        test_strategies=detect_test_strategies(
            files
        ),
    )


def save_profile(
    profile: ProjectProfile,
) -> None:
    LOG_FOLDER.mkdir(
        parents=True,
        exist_ok=True,
    )

    with PROFILE_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            asdict(profile),
            file,
            indent=4,
        )


def print_profile(
    profile: ProjectProfile,
) -> None:
    print("=" * 50)
    print(
        "AI DEVELOPER OVERSEER - PROJECT DISCOVERY"
    )
    print("=" * 50)

    print()
    print(f"Path: {profile.path}")
    print(f"Files: {profile.total_files}")

    print()
    print("Languages:")

    if profile.languages:
        for language in profile.languages:
            print(
                f"  {language.name}: "
                f"{language.files} files "
                f"({language.percentage}%)"
            )
    else:
        print("  None detected")

    print()

    if profile.primary_language is not None:
        print(
            f"Primary language: "
            f"{profile.primary_language}"
        )
    else:
        print("Primary language: None")

    print(
        f"Project type: "
        f"{profile.project_type or 'None'}"
    )

    print()
    print("Tools:")

    if profile.tools:
        for tool in profile.tools:
            print(f"  {tool}")
    else:
        print("  None detected")

    print()
    print("Package managers:")

    if profile.package_managers:
        for manager in profile.package_managers:
            print(f"  {manager}")
    else:
        print("  None detected")

    print()
    print("Project files:")

    if profile.project_files:
        for project_file in profile.project_files:
            print(f"  {project_file}")
    else:
        print("  None detected")

    print()
    print("Dependencies:")

    if profile.dependencies:
        for dependency in profile.dependencies:
            print(
                f"  {dependency.name} "
                f"({dependency.source})"
            )
    else:
        print("  None detected")

    print()
    print("Configuration files:")

    if profile.configuration_files:
        for configuration_file in (
            profile.configuration_files
        ):
            print(
                f"  {configuration_file}"
            )
    else:
        print("  None detected")

    print()
    print("Test strategies:")

    if profile.test_strategies:
        for strategy in profile.test_strategies:
            command = " ".join(
                strategy.command
            )

            print(
                f"  {strategy.framework}: "
                f"{command} "
                f"(from {strategy.source})"
            )
    else:
        print("  None detected")

    print()
    print(
        "Directories discovered: "
        f"{len(profile.directories)}"
    )

    print("-" * 50)


def main() -> None:
    profile = scan_project()

    save_profile(profile)
    print_profile(profile)


if __name__ == "__main__":
    main()