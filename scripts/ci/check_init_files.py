#!/usr/bin/env python3
import re
import sys


def check_file(filepath: str) -> list[str]:
    with open(filepath, encoding="utf-8") as f:
        lines = f.readlines()

    errors = []
    for i, original_line in enumerate(lines):
        line = original_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue

        # Allow: imports, __all__, __version__, __author__, etc.
        if line.startswith("import ") or line.startswith("from "):
            continue
        if line.startswith("__") and "=" in line:
            continue
        if line.startswith(")") or line.startswith(
            "]"
        ):  # Allow closing brackets for multiline imports/__all__
            continue
        if line.startswith('"') or line.startswith(
            "'"
        ):  # Allow string literals (docstrings)
            pass

        # Heuristic: Detect func/class defs, variable assignments (non-dunder), logic
        if re.match(r"^(def |class |if |for |while |try:|with |async )", line):
            errors.append(f"Line {i + 1}: Found logic code '{line}'")
        elif "=" in line and not line.startswith("__"):
            # Assigning variables that are not dunder
            # Check if it's inside __all__?
            # __all__ = [...] is allowed.
            # x = 1 is not.
            errors.append(f"Line {i + 1}: Found variable assignment '{line}'")

    return errors


def main() -> None:
    has_errors = False
    for filepath in sys.argv[1:]:
        errors = check_file(filepath)
        if errors:
            print(f"FAILED: {filepath} contains non-declarative code:")
            for err in errors:
                print(f"  {err}")
            has_errors = True

    if has_errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
