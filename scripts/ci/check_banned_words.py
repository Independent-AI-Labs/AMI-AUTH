#!/usr/bin/env python3
"""
Enforces banned word/pattern policies across the codebase.

Configuration is loaded from res/config/banned_words.yaml (v3.0.0 format):
- banned: list of {pattern, reason, exception_regex?}
- directory_rules: dict of directory -> list of {pattern, reason, exception_regex?}
- filename_rules: list of {pattern, reason}
- ignored_files: files to skip during scanning
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import TypedDict, cast

import yaml

DEFAULT_CONFIG_PATH = "res/config/banned_words.yaml"

# Directories to always ignore
IGNORE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "dist",
    "build",
    ".next",
    "out",
    "checkpoints",
    "logs",
    "results",
    "mlruns",
    ".gemini",
    "rocm_artifacts",
    "tmp",
    "projects",
    ".boot-linux",
    ".boot-macos",
    ".gcloud",
    ".cache",
    ".local",
    "venv",
    "env",
    ".env",
    "site-packages",
    "vendor",
    "ansible",
    ".tox",
    ".nox",
    "htmlcov",
    ".coverage",
    "eggs",
    ".eggs",
}

# File extensions to check
INCLUDE_EXTENSIONS = {".py", ".js", ".ts"}


class PatternConfig(TypedDict, total=False):
    """Configuration for a single pattern rule."""

    pattern: str
    reason: str
    exception_regex: str


class DirectoryRule(TypedDict):
    """A directory rule mapping."""

    directory: str
    patterns: list[PatternConfig]


class BannedWordsConfig(TypedDict, total=False):
    """Configuration for banned words checking."""

    banned: list[PatternConfig]
    directory_rules: object  # Parsed from YAML, structure validated at runtime
    filename_rules: list[PatternConfig]
    ignored_files: list[str]
    ignore_dirs: list[str]


class PatternRule:
    """A single pattern rule with reason and optional exception."""

    def __init__(self, config: PatternConfig):
        self.pattern = config["pattern"]
        self.reason = config["reason"]
        self.exception_regex = config.get("exception_regex")

        # Pre-compile main pattern
        try:
            self._compiled: re.Pattern[str] | None = re.compile(self.pattern)
        except re.error:
            self._compiled = None

        # Pre-compile exception pattern
        self._exception_compiled: re.Pattern[str] | None = None
        if self.exception_regex:
            try:
                self._exception_compiled = re.compile(self.exception_regex)
            except re.error:
                self._exception_compiled = None

    def matches(self, line: str, filepath: str) -> bool:
        """Check if pattern matches line, respecting exceptions."""
        # Check if file is excepted
        if self._exception_compiled and self._exception_compiled.search(filepath):
            return False

        # Try regex match
        if self._compiled:
            return bool(self._compiled.search(line))

        # Fall back to literal match
        return self.pattern in line


def load_config(config_path: str) -> BannedWordsConfig:
    """Load banned words configuration."""
    if not os.path.exists(config_path):
        print(f"Error: Configuration file {config_path} not found.")
        sys.exit(1)
    with open(config_path) as f:
        loaded = yaml.safe_load(f)
        if not loaded:
            return cast(BannedWordsConfig, {})
        return cast(BannedWordsConfig, loaded)


def find_matching_rules(
    line: str, filepath: str, rules: list[PatternRule]
) -> list[PatternRule]:
    """Find all rules that match the given line."""
    return [rule for rule in rules if rule.matches(line, filepath)]


class BannedPatternError(TypedDict):
    """Error information for a banned pattern match."""

    file: str
    line: int
    pattern: str
    reason: str
    content: str


def check_file_content(
    filepath: str,
    global_rules: list[PatternRule],
    dir_rules: list[PatternRule],
) -> list[BannedPatternError]:
    """Check file content for banned patterns."""
    all_rules = global_rules + dir_rules

    if not all_rules:
        return []

    errors: list[BannedPatternError] = []

    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                matched = find_matching_rules(line, filepath, all_rules)
                errors.extend(
                    {
                        "file": filepath,
                        "line": line_num,
                        "pattern": rule.pattern,
                        "reason": rule.reason,
                        "content": line.strip()[:80],
                    }
                    for rule in matched
                )
    except OSError:
        return []

    return errors


def check_filename(
    filepath: str,
    filename_rules: list[PatternRule],
) -> list[BannedPatternError]:
    """Check if filename matches any banned patterns."""
    filename = os.path.basename(filepath)
    matched = [rule for rule in filename_rules if rule.matches(filename, filepath)]

    return [
        BannedPatternError(
            file=filepath,
            line=0,
            pattern=rule.pattern,
            reason=rule.reason,
            content=filename,
        )
        for rule in matched
    ]


# Cache for pre-compiled directory rules (keyed by directory name)
_dir_rules_cache: dict[str, list[PatternRule]] = {}


def get_dir_rules(filepath: str, dir_rules_compiled: object) -> list[PatternRule]:
    """Get rules that apply based on file's directory."""
    rules: list[PatternRule] = []
    if not isinstance(dir_rules_compiled, dict):
        return rules
    path = Path(filepath)

    for dir_name, compiled_rules in dir_rules_compiled.items():
        if dir_name in path.parts:
            rules.extend(compiled_rules)

    return rules


def compile_dir_rules(
    dir_rules_config: object,
) -> dict[str, list[PatternRule]]:
    """Pre-compile all directory rules."""
    if not isinstance(dir_rules_config, dict):
        return {}
    return {
        str(dir_name): [PatternRule(cfg) for cfg in rule_configs]
        for dir_name, rule_configs in dir_rules_config.items()
        if isinstance(rule_configs, list)
    }


def print_errors(errors: list[BannedPatternError]) -> None:
    """Print errors grouped by file with reasons."""
    print(f"\n\033[91mFAILED: {len(errors)} banned pattern(s) found:\033[0m\n")

    # Group by file
    by_file: dict[str, list[BannedPatternError]] = {}
    for err in errors:
        key = str(err["file"])
        if key not in by_file:
            by_file[key] = []
        by_file[key].append(err)

    for filepath, file_errors in sorted(by_file.items()):
        print(f"\033[1m{filepath}\033[0m")
        for err in file_errors:
            line_info = f":{err['line']}" if err["line"] else ""
            print(f"  Line{line_info}: \033[93m{err['pattern']}\033[0m")
            print(f"    Reason: \033[96m{err['reason']}\033[0m")
            if err["content"]:
                print(f"    > {err['content']}")
        print()


def _list_tracked_files(root_dir: str, ignore_dirs: set[str]) -> list[str]:
    """Return relative paths of files to scan.

    Prefers ``git ls-files`` so gitignored build artifacts are skipped.
    Falls back to ``os.walk`` when not inside a git repository.
    """
    git_paths = _git_ls_files(root_dir, ignore_dirs)
    if git_paths is not None:
        return git_paths

    # Fallback: walk filesystem
    paths: list[str] = []
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for filename in files:
            filepath = os.path.join(root, filename)
            paths.append(os.path.relpath(filepath, root_dir))
    return paths


def _git_ls_files(root_dir: str, ignore_dirs: set[str]) -> list[str] | None:
    """Return tracked file paths via git, or None if not in a git repo."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            capture_output=True,
            text=True,
            cwd=root_dir,
            check=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    paths: list[str] = []
    for entry in result.stdout.splitlines():
        stripped = entry.strip()
        if not stripped:
            continue
        parts = Path(stripped).parts
        if any(p in ignore_dirs for p in parts):
            continue
        paths.append(stripped)
    return paths


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Check for banned words/patterns")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to config file (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--exclude-dir",
        action="append",
        default=[],
        dest="exclude_dirs",
        help="Additional directory names to ignore (repeatable)",
    )
    args = parser.parse_args()

    config = load_config(args.config)

    # Parse configuration
    banned_configs = config.get("banned", [])
    dir_rules_config = config.get("directory_rules", {})
    filename_configs = config.get("filename_rules", [])
    ignored_files = set(config.get("ignored_files", []))

    # Merge config-level + CLI ignore_dirs with built-in IGNORE_DIRS
    extra_ignore: set[str] = set(config.get("ignore_dirs", []))
    extra_ignore.update(args.exclude_dirs)
    effective_ignore_dirs = IGNORE_DIRS | extra_ignore

    # Pre-compile all rule objects
    global_rules = [PatternRule(cfg) for cfg in banned_configs]
    filename_rules = [PatternRule(cfg) for cfg in filename_configs]
    dir_rules_compiled = compile_dir_rules(dir_rules_config)

    errors: list[BannedPatternError] = []
    root_dir = os.getcwd()
    files_checked = 0

    print("Scanning repository for banned patterns...")
    print(f"  Global rules: {len(global_rules)}")
    dir_rule_count = sum(len(v) for v in dir_rules_compiled.values())
    print(f"  Directory-specific rules: {dir_rule_count}")
    print(f"  Filename rules: {len(filename_rules)}")

    # Use git ls-files if inside a git repo to respect .gitignore;
    # fall back to os.walk for non-git contexts.
    tracked_files = _list_tracked_files(root_dir, effective_ignore_dirs)

    for rel_path in tracked_files:
        filename = os.path.basename(rel_path)

        if not any(filename.endswith(ext) for ext in INCLUDE_EXTENSIONS):
            continue

        if rel_path in ignored_files or filename in ignored_files:
            continue

        files_checked += 1

        # Check filename
        errors.extend(check_filename(rel_path, filename_rules))

        # Get directory-specific rules (using pre-compiled rules)
        dir_rules = get_dir_rules(rel_path, dir_rules_compiled)

        # Check content
        errors.extend(check_file_content(rel_path, global_rules, dir_rules))

    print(f"  Files checked: {files_checked}")

    if errors:
        print_errors(errors)
        sys.exit(1)

    print("\033[92mSUCCESS: No banned patterns found.\033[0m")
    sys.exit(0)


if __name__ == "__main__":
    main()
