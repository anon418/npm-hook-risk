"""npm-hook-risk 공개 preview CLI.

CLI 계층은 의도적으로 얇게 유지한다. 입력 검증, exact package@version 다운로드,
분석 호출, 사용자용 review-priority 출력 변환만 담당하며 scoring 의미는 바꾸지 않는다.
"""

from __future__ import annotations

import argparse
import json
import sys
import traceback
from dataclasses import dataclass
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from cli.presenter import FAILURE_STATUSES, build_user_summary, render_explain, render_summary
from tools.analyze_package import HOOKS, analyze_package_dir, read_package_json

from . import ENGINE_PROFILE, LEGACY_RECORDED_RULE_HASH, REVIEW_PRIORITY_MODEL, TOOL_VERSION
from .provenance import build_public_engine_manifest, write_manifest
from .registry import RegistryError, fetch_package_to_temp, parse_package_spec

EXIT_OK = 0
EXIT_USAGE = 1
EXIT_ANALYSIS_FAILED = 2
EXIT_STRICT_HIGH = 3
EXIT_UNSUPPORTED = 4
EXIT_OUTPUT_FAILED = 5
EXIT_REGISTRY_FAILED = 6

USAGE_HINT = "Usage:\n  npm-hook-risk scan <package-directory|package@version>"


@dataclass
class ScanOutcome:
    raw_result: dict[str, Any]
    terminal_status: str


class CliError(Exception):
    exit_code = EXIT_USAGE


class InputError(CliError):
    exit_code = EXIT_USAGE


class AnalysisError(CliError):
    exit_code = EXIT_ANALYSIS_FAILED


class OutputError(CliError):
    exit_code = EXIT_OUTPUT_FAILED


class PublicRegistryError(CliError):
    exit_code = EXIT_REGISTRY_FAILED


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="npm-hook-risk",
        description=(
            "Static review-priority triage for npm lifecycle hooks. "
            "This preview does not execute package scripts or provide a malicious verdict."
        ),
    )
    parser.add_argument("--version", action="version", version=f"npm-hook-risk {TOOL_VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Analyze a package directory or exact package@version")
    scan.add_argument("target", nargs="?", help="Package directory or exact package@version")
    output_group = scan.add_mutually_exclusive_group()
    output_group.add_argument("--details", action="store_true", help="Print detailed evidence provenance")
    output_group.add_argument("--json", action="store_true", help="Print stable user-facing JSON")
    output_group.add_argument("--raw-json", action="store_true", help=argparse.SUPPRESS)
    output_group.add_argument("--summary", action="store_true", help=argparse.SUPPRESS)
    output_group.add_argument("--explain", action="store_true", help=argparse.SUPPRESS)
    scan.add_argument("--output", metavar="PATH", help="Write JSON output to PATH")
    scan.add_argument("--strict", action="store_true", help="Exit nonzero for High priority or failure status")
    scan.add_argument("--debug", action="store_true", help="Show Python traceback for debugging")
    scan.set_defaults(func=run_scan)

    manifest = subparsers.add_parser("manifest", help="Write public preview engine source manifest")
    manifest.add_argument("--output", default="provenance/public_engine_manifest.json")
    manifest.set_defaults(func=run_manifest)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        print(f"npm-hook-risk: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return exc.exit_code
    except Exception as exc:
        print(f"npm-hook-risk: analysis failed: {exc}", file=sys.stderr)
        if getattr(args, "debug", False):
            traceback.print_exc()
        return EXIT_ANALYSIS_FAILED


def run_manifest(args: argparse.Namespace) -> int:
    try:
        manifest = write_manifest(_repo_root(), Path(args.output))
    except Exception as exc:
        raise OutputError(str(exc)) from exc
    print(json.dumps(manifest, indent=2, ensure_ascii=False))
    return EXIT_OK


def run_scan(args: argparse.Namespace) -> int:
    # 공개 명령은 예측 가능해야 한다: 대상 하나, 분석 한 번, 출력 모드 하나.
    # 출력 형식 선택이 실제 분석 결과를 바꾸면 재현성이 깨진다.
    if not args.target:
        raise InputError(f"missing scan target\n\n{USAGE_HINT}")
    if args.summary:
        print("npm-hook-risk: --summary is deprecated; summary is the default", file=sys.stderr)
    if args.explain:
        print("npm-hook-risk: --explain is deprecated; use --details", file=sys.stderr)
        args.details = True

    spec = parse_package_spec(args.target)
    if spec and not Path(args.target).exists():
        outcome = scan_package_spec(spec)
    else:
        outcome = scan_local_directory(Path(args.target))

    raw = outcome.raw_result
    summary = build_user_summary({**raw, "terminal_status": outcome.terminal_status})
    output_payload = raw if args.raw_json else summary
    if args.output:
        _write_json(Path(args.output), output_payload)

    if args.raw_json:
        print(json.dumps(raw, indent=2, ensure_ascii=False))
    elif args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
    elif args.details:
        print(render_explain(raw, summary))
    else:
        print(render_summary(summary))
    return _exit_code(summary, args.strict)


def scan_package_spec(spec: Any) -> ScanOutcome:
    # registry 분석은 exact package@version만 허용한다. 다운로드 후 integrity를 검증하고
    # 임시 디렉터리에 안전하게 푼 뒤 로컬 디렉터리 분석과 같은 경로로 보낸다.
    try:
        temporary = fetch_package_to_temp(spec)
    except RegistryError as exc:
        raise PublicRegistryError(str(exc)) from exc
    with temporary:
        return scan_local_directory(Path(temporary.name) / "package")


def scan_local_directory(target: Path) -> ScanOutcome:
    # 분석 전에 package 구조를 확인해 사용자 실수를 traceback 대신 명확한 CLI 오류로 돌려준다.
    package_dir = target.expanduser().resolve()
    if not package_dir.exists():
        raise InputError(f"package directory was not found:\n{package_dir}\n\n{USAGE_HINT}")
    if not package_dir.is_dir():
        raise InputError(f"target is not a directory:\n{package_dir}\n\n{USAGE_HINT}")
    package_json = package_dir / "package.json"
    if not package_json.exists():
        raise InputError(f"package.json was not found in:\n{package_dir}\n\n{USAGE_HINT}")
    try:
        pkg = read_package_json(package_dir)
    except JSONDecodeError as exc:
        raise InputError(f"package.json is malformed:\n{package_json}\n{exc}") from exc
    scripts = pkg.get("scripts") or {}
    lifecycle = {hook: scripts.get(hook) for hook in HOOKS if isinstance(scripts.get(hook), str)}
    if lifecycle:
        # 미지원 lifecycle command는 명시적인 검토 상태다. 실제 JS 근거를 분석하지 않았으므로
        # Low로 낮춰 표시하면 안전하다는 오해를 만든다.
        unsupported = _unsupported_commands(lifecycle)
        if unsupported and len(unsupported) == len(lifecycle):
            return ScanOutcome(
                _minimal_raw_result(package_dir, pkg, lifecycle, "unsupported_language", unsupported),
                "unsupported_language",
            )
    try:
        raw = analyze_package_dir(package_dir)
    except Exception as exc:
        raise AnalysisError(str(exc)) from exc
    terminal_status = "success" if raw.get("hooks_found") else "no_hook"
    return ScanOutcome({**raw, "terminal_status": terminal_status}, terminal_status)


def _unsupported_commands(lifecycle: dict[str, str]) -> dict[str, str]:
    # 공개 preview는 로컬 JavaScript 실행과 inline node eval만 분석한다. native build,
    # shell wrapper, 임의 interpreter는 수동 검토가 필요한 unsupported 상태로 남긴다.
    unsupported = {}
    for hook, command in lifecycle.items():
        normalized = command.strip().lower()
        if normalized in {"true", "exit 0", "node -e \"\"", "node -e ''"}:
            continue
        if _has_local_js_invocation(command) or "node -e" in normalized or "node --eval" in normalized:
            continue
        unsupported[hook] = command
    return unsupported


def _has_local_js_invocation(command: str) -> bool:
    import re

    return bool(re.search(r"(?:^|\s)(?:node\s+)?(?:\./)?[A-Za-z0-9_./@-]+\.(?:c|m)?js\b", command))


def _minimal_raw_result(package_dir: Path, pkg: dict[str, Any], lifecycle: dict[str, str], status: str, unsupported: dict[str, str]) -> dict[str, Any]:
    return {
        "package": pkg.get("name"),
        "version": pkg.get("version"),
        "path": str(package_dir),
        "terminal_status": status,
        "hooks_found": list(lifecycle.keys()),
        "hooks": {
            hook: {
                "command": command,
                "categories": [],
                "matched_patterns": {},
                "deobfuscation_findings": [],
                "taint_paths": [],
                "taint_path_count": 0,
                "score": 0,
                "risk_level": "Unavailable",
                "reasons": [],
            }
            for hook, command in lifecycle.items()
        },
        "taint_paths": [],
        "taint_path_count": 0,
        "reachable_files": [],
        "final_score": None,
        "final_risk_level": None,
        "analysis_failures": [f"Unsupported command: {hook}: {command}" for hook, command in unsupported.items()],
    }


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    except OSError as exc:
        raise OutputError(f"could not write output file:\n{path}\n{exc}") from exc


def _exit_code(summary: dict[str, Any], strict: bool) -> int:
    status = str(summary.get("analysis_status", {}).get("status") or summary.get("terminal_status"))
    priority = summary.get("review_priority", {}).get("level") if isinstance(summary.get("review_priority"), dict) else summary.get("review_priority")
    if status == "unsupported_language":
        return EXIT_UNSUPPORTED if strict else EXIT_OK
    if status in FAILURE_STATUSES:
        return EXIT_ANALYSIS_FAILED if strict else EXIT_OK
    if strict and priority == "high":
        return EXIT_STRICT_HIGH
    return EXIT_OK


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]
