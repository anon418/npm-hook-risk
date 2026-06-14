#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

HOOKS = ["preinstall", "install", "postinstall"]

KEYWORDS = [
    r"process\.env",
    r"https?://",
    r"\bcurl\b",
    r"\bwget\b",
    r"child_process",
    r"\bexec\s*\(",
    r"\bspawn\s*\(",
    r"\beval\s*\(",
    r"base64",
    r"Buffer\.from",
    r"powershell",
    r"(^|[\s;&|])bash(\s|$)",
    r"(^|[\s;&|])sh(\s|$)",
]


def read_package_json(package_dir: Path):
    path = package_dir / "package.json"
    if not path.exists():
        raise FileNotFoundError(f"package.json not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def collect_sources(package_dir: Path, scripts: dict):
    sources = {}

    for hook in HOOKS:
        command = scripts.get(hook)
        if not command:
            continue

        text = command + "\n"

        for token in command.split():
            if token.endswith(".js"):
                js_path = package_dir / token
                if js_path.exists():
                    text += "\n" + js_path.read_text(
                        encoding="utf-8",
                        errors="ignore"
                    )

        sources[hook] = text

    return sources


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <package_dir>", file=sys.stderr)
        sys.exit(1)

    package_dir = Path(sys.argv[1]).resolve()
    pkg = read_package_json(package_dir)
    scripts = pkg.get("scripts", {})
    sources = collect_sources(package_dir, scripts)

    result = {
        "package": pkg.get("name"),
        "version": pkg.get("version"),
        "matches": {},
        "baseline_flagged": False,
        "baseline_risk": "Low"
    }

    total_matches = 0

    for hook, text in sources.items():
        hook_matches = []
        for keyword in KEYWORDS:
            if re.search(keyword, text, re.IGNORECASE):
                hook_matches.append(keyword)

        if hook_matches:
            result["matches"][hook] = hook_matches
            total_matches += len(hook_matches)

    if total_matches > 0:
        result["baseline_flagged"] = True
        result["baseline_risk"] = "High"

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
