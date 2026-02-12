#!/usr/bin/env python3
import os
import sys
from typing import Any

import yaml

DEFAULT_CONFIG = {
    "forbidden_patterns": [
        # Standard variations
        "Co-authored-by:",
        "Co-Authored-By:",
        "Co-Authored-by:",
        "Co-authored-By:",
        "co-authored-by:",
        "CO-AUTHORED-BY:",
        # Without colon
        "Co-authored-by",
        "Co-Authored-By",
        "Co-Authored-by",
        "Co-authored-By",
        "co-authored-by",
        "CO-AUTHORED-BY",
        # Underscore variations
        "Co_authored_by:",
        "Co_Authored_By:",
        "co_authored_by:",
        "Co_authored_by",
        "Co_Authored_By",
        "co_authored_by",
        # No hyphen/underscore
        "Coauthoredby:",
        "CoAuthoredBy:",
        "coauthoredby:",
        "Coauthoredby",
        "CoAuthoredBy",
        "coauthoredby",
        # Space variations
        "Co authored by:",
        "Co Authored By:",
        "co authored by:",
        "Co authored by",
        "Co Authored By",
        "co authored by",
        # Common misspellings
        "Co-author-by:",
        "Co-Author-By:",
        "Coauthor-by:",
        "CoAuthor-By:",
        # Anthropic signature
        "noreply@anthropic.com",
        "Claude",
    ],
    "error_message": "FAILED: Co-authored commits are forbidden in this repository.",
}


def load_config(
    config_path: str = "res/config/commit_checks.yaml",
) -> Any:
    if os.path.exists(config_path):
        with open(config_path) as f:
            return yaml.safe_load(f)
    return DEFAULT_CONFIG


def main() -> None:
    config = load_config()
    forbidden_patterns = config.get("forbidden_patterns", [])
    error_msg = config.get("error_message", "Error: Forbidden pattern found.")

    # Pre-commit passes the commit message file as the first argument
    MIN_ARGS = 2

    if len(sys.argv) < MIN_ARGS:
        print("Error: No commit message file provided.")
        sys.exit(1)

    commit_msg_file = sys.argv[1]

    if not os.path.exists(commit_msg_file):
        print(f"Error: Commit message file {commit_msg_file} not found.")
        sys.exit(1)

    with open(commit_msg_file) as f:
        content = f.read()

    for pattern in forbidden_patterns:
        if pattern in content:
            print(f"\n\033[91m{error_msg}\033[0m")
            print(f"Found forbidden pattern: '{pattern}'")
            print("Please remove it from your commit message.")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
