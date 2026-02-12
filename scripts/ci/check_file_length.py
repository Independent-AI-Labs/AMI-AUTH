#!/usr/bin/env python3
"""
Enforces a maximum line count for source files.
Configuration is loaded from res/config/file_length_limits.yaml
"""

import os
import sys
from typing import NamedTuple, TypedDict

import yaml


class FileViolation(NamedTuple):
    """A file that violates a policy."""

    filepath: str
    line_count: int


CONFIG_PATH = "res/config/file_length_limits.yaml"


class FileLengthConfig(TypedDict, total=False):
    """Configuration for file length checking."""

    max_lines: int
    extensions: list[str]
    ignore_files: list[str]
    ignore_dirs: list[str]


DEFAULT_CONFIG: FileLengthConfig = {
    "max_lines": 512,
    "extensions": [".py", ".sh", ".js", ".ts"],
    "ignore_files": [],
    "ignore_dirs": [
        ".git",
        ".venv",
        "node_modules",
        "dist",
        "build",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "projects",
    ],
}


def load_config() -> FileLengthConfig:
    """Load configuration from file or use defaults."""
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f) or DEFAULT_CONFIG
    print(f"Warning: {CONFIG_PATH} not found, using defaults")
    return DEFAULT_CONFIG


def get_all_files(ignore_dirs: set[str], valid_extensions: list[str]) -> list[str]:
    """Get all files matching extensions, excluding ignored directories."""
    ext_tuple = tuple(valid_extensions)
    files_to_check: list[str] = []
    for root, dirs, filenames in os.walk("."):
        # Filter dirs in-place
        dirs[:] = [d for d in dirs if d not in ignore_dirs]

        files_to_check.extend(
            os.path.join(root, f) for f in filenames if f.endswith(ext_tuple)
        )
    return files_to_check


def should_check_file(
    file_path: str,
    valid_extensions: list[str],
    ignore_files: set[str],
    ignore_dirs: set[str],
) -> bool:
    """Determine if a file should be checked."""
    ext_tuple = tuple(valid_extensions)
    if not file_path.endswith(ext_tuple):
        return False

    if os.path.basename(file_path) in ignore_files:
        return False

    if not os.path.isfile(file_path):
        return False

    # Check if file is inside an ignored directory
    parts = file_path.split(os.sep)
    return not any(part in ignore_dirs for part in parts)


def check_file_length(file_path: str, max_lines: int) -> int | None:
    """Check a file's line count. Returns line count if over limit, None otherwise."""
    try:
        with open(file_path, encoding="utf-8", errors="ignore") as f:
            line_count = sum(1 for _ in f)
            if line_count > max_lines:
                return line_count
    except OSError as e:
        print(f"Error reading {file_path}: {e}")
    return None


def print_violations(violations: list[FileViolation], max_lines: int) -> None:
    """Print violation report."""
    num_violations = len(violations)
    print(
        f"\n\033[91mFAILED: {num_violations} file(s) exceed {max_lines} lines:\033[0m\n"
    )
    for violation in sorted(violations, key=lambda x: -x.line_count):
        excess = violation.line_count - max_lines
        path = violation.filepath
        lines = violation.line_count
        print(f"  \033[1m{path}\033[0m: {lines} lines (+{excess} over limit)")
    print()


def main() -> None:
    """Main entry point."""
    config = load_config()
    max_lines = config.get("max_lines", 512)

    valid_extensions = config.get("extensions", [".py", ".sh", ".js", ".ts"])

    ignore_files = set(config.get("ignore_files", []))
    ignore_dirs = set(config.get("ignore_dirs", []))

    violations: list[FileViolation] = []

    # Pre-commit passes the list of changed files as arguments
    files = sys.argv[1:] or get_all_files(ignore_dirs, valid_extensions)

    print(f"Checking file lengths (max {max_lines} lines)...")

    for file_path in files:
        if not should_check_file(
            file_path, valid_extensions, ignore_files, ignore_dirs
        ):
            continue

        line_count = check_file_length(file_path, max_lines)
        if line_count is not None:
            violations.append(FileViolation(file_path, line_count))

    if violations:
        print_violations(violations, max_lines)
        sys.exit(1)

    print(f"\033[92mSUCCESS: All files within {max_lines} line limit.\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
