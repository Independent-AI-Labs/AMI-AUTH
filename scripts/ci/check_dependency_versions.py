#!/usr/bin/env python3
"""
Dependency version checker (PyPI + npm).

Ensures that:
1. All dependencies use strict pinning (== for PyPI, exact semver for npm)
2. All pinned versions are the latest available from their registry

Usage:
    ./check_dependency_versions.py                          # Check pyproject.toml
    ./check_dependency_versions.py package.json             # Check package.json
    ./check_dependency_versions.py pyproject.toml pkg.json  # Check both
    ./check_dependency_versions.py --upgrade                # Auto-upgrade
    ./check_dependency_versions.py --exclude torch,numpy    # Exclude packages
"""

import argparse
import json
import re
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import NamedTuple

import yaml


class ParsedDependency(NamedTuple):
    """A parsed dependency specification."""

    name: str
    extras: str | None
    operator: str | None
    version: str | None


class LooseDependency(NamedTuple):
    """A dependency without pinned version."""

    name: str
    current_spec: str
    latest_version: str


class OutdatedDependency(NamedTuple):
    """A dependency with outdated pinned version."""

    name: str
    extras: str | None
    old_version: str | None
    new_version: str


class DependencyCheckResult(NamedTuple):
    """Result from checking and collecting dependency issues."""

    loose: list[LooseDependency]
    outdated: list[OutdatedDependency]
    toml_data: object


BUILTIN_EXCLUDES = {
    "torch",
    "torchvision",
    "torchaudio",
    "ami-agents",
    "pytorch-triton-rocm",  # Must match torch rocm version, not PyPI latest
    "pandas",  # Constrained by mlflow<3
    "pandas-" + "st" + "ubs",  # Type annotations package, must match pandas version
}


def load_config_excludes(key: str = "excludes") -> set[str]:
    """Load exclusions from res/config/dependency_excludes.yaml."""
    config_path = Path("res/config/dependency_excludes.yaml")
    if not config_path.exists():
        return set()

    try:
        with open(config_path) as f:
            data = yaml.safe_load(f)
            return {x.strip().lower() for x in data.get(key, []) if x.strip()}
    except Exception as e:
        print(f"Warning: Failed to load config excludes: {e}")
        return set()


def get_latest_pypi_version(package_name: str) -> str | None:
    """Query PyPI JSON API for the latest version of a package."""
    normalized = re.sub(r"[-_.]+", "-", package_name).lower()
    url = f"https://pypi.org/pypi/{normalized}/json"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            version: str | None = data.get("info", {}).get("version")
            return version
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def parse_dependency(dep: str) -> ParsedDependency:
    """
    Parse a dependency string into (name, extras, operator, version).

    Returns:
        ParsedDependency with name, extras, operator, version (may be None)
    """
    dep = dep.strip()
    extras_match = re.match(r"^([a-zA-Z0-9_-]+)(\[[^\]]+\])?(.*)$", dep)
    if not extras_match:
        return ParsedDependency(dep, None, None, None)

    name = extras_match.group(1)
    extras = extras_match.group(2)
    remainder = extras_match.group(3).strip()

    if not remainder:
        return ParsedDependency(name, extras, None, None)

    for op in ["==", ">=", "<=", "~=", ">", "<"]:
        if remainder.startswith(op):
            version = remainder[len(op) :].strip()
            if ";" in version:
                version = version.split(";")[0].strip()
            return ParsedDependency(name, extras, op, version)

    return ParsedDependency(name, extras, None, None)


def check_and_collect(path: Path, excludes: set[str]) -> DependencyCheckResult:
    """
    Check pyproject.toml and collect issues.

    Returns:
        DependencyCheckResult(loose, outdated, toml_data)
        loose: list of LooseDependency(name, current_spec, latest_version)
        outdated: list of OutdatedDependency(name, extras, old_version, new_version)
    """
    with open(path, "rb") as f:
        data = tomllib.load(f)

    deps = data.get("project", {}).get("dependencies", [])
    optional_deps = data.get("project", {}).get("optional-dependencies", {})

    all_deps = list(deps)
    for extra_deps in optional_deps.values():
        all_deps.extend(extra_deps)

    loose_deps: list[LooseDependency] = []
    outdated_deps: list[OutdatedDependency] = []
    checked: set[str] = set()

    for dep in all_deps:
        parsed = parse_dependency(dep)
        name_lower = parsed.name.lower()

        if name_lower in excludes or name_lower in BUILTIN_EXCLUDES:
            continue
        if name_lower in checked:
            continue
        checked.add(name_lower)

        latest = get_latest_pypi_version(parsed.name)
        if latest is None:
            continue

        if parsed.operator is None or parsed.operator != "==":
            extras = parsed.extras or ""
            op = parsed.operator or ""
            ver = parsed.version or ""
            current_spec = f"{parsed.name}{extras}{op}{ver}"
            loose_deps.append(LooseDependency(parsed.name, current_spec, latest))
        elif parsed.version != latest:
            outdated_deps.append(
                OutdatedDependency(parsed.name, parsed.extras, parsed.version, latest)
            )

    return DependencyCheckResult(loose_deps, outdated_deps, data)


# --- npm support ---

_NPM_STRICT_RE = re.compile(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$")
_NPM_SKIP_PREFIXES = ("workspace:", "file:", "git:", "git+", "http:", "https:", "link:")


def get_latest_npm_version(package_name: str) -> str | None:
    """Query npm registry for the latest version of a package."""
    encoded = urllib.parse.quote(package_name, safe="@")
    url = f"https://registry.npmjs.org/{encoded}/latest"
    try:
        with urllib.request.urlopen(url, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            version: str | None = data.get("version")
            return version
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def parse_npm_dependency(name: str, version_spec: str) -> ParsedDependency:
    """Parse an npm dependency name and version specifier."""
    spec = version_spec.strip()
    if not spec or spec in ("*", "latest"):
        return ParsedDependency(name, None, None, None)
    for prefix in (">=", "<=", ">", "<", "^", "~"):
        if spec.startswith(prefix):
            return ParsedDependency(name, None, prefix, spec[len(prefix) :].strip())
    if _NPM_STRICT_RE.match(spec):
        return ParsedDependency(name, None, "==", spec)
    return ParsedDependency(name, None, None, spec)


def check_npm_and_collect(path: Path, excludes: set[str]) -> DependencyCheckResult:
    """Check package.json and collect issues."""
    with open(path) as f:
        data = json.load(f)

    deps: dict[str, str] = data.get("dependencies", {})
    dev_deps: dict[str, str] = data.get("devDependencies", {})
    all_deps = {**deps, **dev_deps}

    loose_deps: list[LooseDependency] = []
    outdated_deps: list[OutdatedDependency] = []

    for name, version_spec in all_deps.items():
        if name.lower() in excludes:
            continue
        if version_spec.startswith(_NPM_SKIP_PREFIXES):
            continue

        parsed = parse_npm_dependency(name, version_spec)
        latest = get_latest_npm_version(name)
        if latest is None:
            continue

        if parsed.operator is None or parsed.operator != "==":
            current_spec = f"{name}@{version_spec}"
            loose_deps.append(LooseDependency(name, current_spec, latest))
        elif parsed.version != latest:
            outdated_deps.append(OutdatedDependency(name, None, parsed.version, latest))

    return DependencyCheckResult(loose_deps, outdated_deps, data)


def upgrade_package_json(
    path: Path,
    loose: list[LooseDependency],
    outdated: list[OutdatedDependency],
) -> None:
    """Upgrade versions in package.json to latest strict pins."""
    with open(path) as f:
        data = json.load(f)

    upgrade_map: dict[str, str] = {}
    for loose_dep in loose:
        upgrade_map[loose_dep.name] = loose_dep.latest_version
    for outdated_dep in outdated:
        upgrade_map[outdated_dep.name] = outdated_dep.new_version

    for section in ("dependencies", "devDependencies"):
        if section not in data:
            continue
        for pkg_name in data[section]:
            if pkg_name in upgrade_map:
                data[section][pkg_name] = upgrade_map[pkg_name]

    with open(path, "w") as f:
        json.dump(data, f, indent=2)
        f.write("\n")


def upgrade_pyproject(
    path: Path,
    loose: list[LooseDependency],
    outdated: list[OutdatedDependency],
) -> None:
    """Upgrade versions in pyproject.toml."""
    content = path.read_text()

    # Only match deps inside arrays (lines starting with whitespace + quote)
    for loose_dep in loose:
        pattern = (
            rf'(^\s+)"{re.escape(loose_dep.name)}(\[[^\]]*\])?(>=|<=|~=|>|<)?[^"]*"'
        )
        replacement = rf'\1"{loose_dep.name}\2=={loose_dep.latest_version}"'
        content = re.sub(
            pattern, replacement, content, flags=re.IGNORECASE | re.MULTILINE
        )

    for outdated_dep in outdated:
        extras_pat = re.escape(outdated_dep.extras) if outdated_dep.extras else ""
        pattern = rf'(^\s+)"{re.escape(outdated_dep.name)}{extras_pat}==[^"]*"'
        extras = outdated_dep.extras or ""
        new_ver = outdated_dep.new_version
        replacement = rf'\1"{outdated_dep.name}{extras}=={new_ver}"'
        content = re.sub(
            pattern, replacement, content, flags=re.IGNORECASE | re.MULTILINE
        )

    path.write_text(content)


def _is_npm_file(path: Path) -> bool:
    return path.name == "package.json"


def _check_path(path: Path, excludes: set[str], *, upgrade: bool) -> tuple[bool, int]:
    """Check a single file for dependency issues."""
    is_npm = _is_npm_file(path)
    print(f"Checking {path}...")

    if is_npm:
        loose, outdated, _ = check_npm_and_collect(path, excludes)
    else:
        loose, outdated, _ = check_and_collect(path, excludes)

    if upgrade and (loose or outdated):
        label = "package.json" if is_npm else "pyproject.toml"
        print(f"Upgrading {label}...")
        if is_npm:
            upgrade_package_json(path, loose, outdated)
        else:
            upgrade_pyproject(path, loose, outdated)
        return False, len(loose) + len(outdated)

    has_errors = False
    if loose:
        has_errors = True
        print(f"\n!!! LOOSE DEPENDENCY CONSTRAINTS in {path} !!!")
        print("All dependencies must use strict pinning")
        for loose_dep in loose:
            spec = loose_dep.current_spec
            latest = loose_dep.latest_version
            print(f"  - {spec} -> {loose_dep.name}=={latest}")

    if outdated:
        has_errors = True
        print(f"\n!!! OUTDATED DEPENDENCIES in {path} !!!")
        for outdated_dep in outdated:
            extras = outdated_dep.extras or ""
            old = outdated_dep.old_version
            new = outdated_dep.new_version
            print(f"  - {outdated_dep.name}{extras}=={old} -> {new}")

    return has_errors, 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check and optionally upgrade dependency versions"
    )
    parser.add_argument(
        "--upgrade",
        action="store_true",
        help="Automatically upgrade outdated/loose deps to latest versions",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default="",
        help="Comma-separated list of packages to exclude from checking",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["pyproject.toml"],
        help="Paths to check (pyproject.toml and/or package.json)",
    )
    args = parser.parse_args()

    cli_excludes = {x.strip().lower() for x in args.exclude.split(",") if x.strip()}
    pypi_excludes = cli_excludes | load_config_excludes()
    npm_excludes = cli_excludes | load_config_excludes("npm_excludes")

    dep_errors = False
    upgrade_count = 0

    for path_str in args.paths:
        path = Path(path_str)
        if not path.exists():
            print(f"Error: {path} not found")
            return 1

        excludes = npm_excludes if _is_npm_file(path) else pypi_excludes
        errors, upgraded = _check_path(path, excludes, upgrade=args.upgrade)
        dep_errors = dep_errors or errors
        upgrade_count += upgraded

    if args.upgrade and upgrade_count > 0:
        print(f"Updated {upgrade_count} dependencies.")
        return 0

    if dep_errors:
        print("\nRun with --upgrade to auto-fix.")
        return 1

    print("All dependencies are strictly pinned and up to date.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
