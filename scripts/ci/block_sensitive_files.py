#!/usr/bin/env python3
"""
Pre-commit hook to block potentially sensitive files from being committed.
Blocks specific extensions if the filename starts with . or contains sensitive keywords.
"""

import sys
from pathlib import Path

# File extensions that are scrutinized
SENSITIVE_EXTENSIONS = {
    ".yaml",
    ".yml",
    ".toml",
    ".json",
    ".xml",
    ".cfg",
    ".ini",
    ".env",
    ".pickle",
    ".key",
    ".crt",
    ".pem",
    ".p12",
    ".pfx",
}

# Keywords that trigger a block if found in the filename (case-insensitive)
SENSITIVE_KEYWORDS = {
    "pass",
    "secret",
    "key",
    "var",
    "cred",
    "vault",
    "token",
    "password",
    "cert",
    "private",
    "id_rsa",
    "id_ed25519",
    "config",
    "env",
}

# Files that are ALWAYS allowed despite matching patterns
SAFE_EXCEPTIONS = {
    "pyproject.toml",
    "uv.lock",
    "poetry.lock",
    "package.json",
    "package-lock.json",
    "requirements.txt",
    "setup.cfg",
    "tox.ini",
    "tsconfig.json",
    ".pre-commit-config.yaml",
}


def is_sensitive(filepath: str) -> bool:
    path = Path(filepath)
    name = path.name.lower()
    ext = path.suffix.lower()

    # Skip explicitly allowed files
    if path.name in SAFE_EXCEPTIONS:
        return False

    # Rule 1: Check if extension is in the sensitive list
    if ext in SENSITIVE_EXTENSIONS or name.startswith(".env"):
        # Rule 2: Check if name starts with . (hidden config)
        if name.startswith("."):
            return True

        # Rule 3: Check if name contains any sensitive keywords
        if any(keyword in name for keyword in SENSITIVE_KEYWORDS):
            return True

    return False


def main() -> None:
    # Pre-commit passes files as arguments

    sensitive_files = [arg for arg in sys.argv[1:] if is_sensitive(arg)]

    if sensitive_files:
        print("\n" + "!" * 60)
        print("CRITICAL SECURITY FAILURE: Sensitive files detected!")
        print("The following files match patterns forbidden for commitment:")
        for f in sensitive_files:
            print(f"  - {f}")
        print("\nREASON: Files with sensitive extensions matching '.' or keywords")
        print("are blocked to prevent accidental secret leakage.")
        print("!" * 60 + "\n")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
