"""npm-hook-risk 결과를 사용자에게 보여주는 presentation 계층.

이 모듈은 분석을 실행하지 않고 scoring rule도 바꾸지 않는다. raw analyzer 결과를
간결한 요약, 상세 설명, 안정적인 사용자용 JSON 스키마로 변환한다.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from npm_hook_risk import (
    ENGINE_PROFILE,
    LEGACY_RECORDED_RULE_HASH,
    REVIEW_PRIORITY_MODEL,
    TOOL_VERSION,
)


ANALYZABLE_STATUSES = {"success", "partial_success"}
FAILURE_STATUSES = {
    "unsupported_language",
    "parse_failure",
    "extraction_failure",
    "analysis_error",
    "timeout",
    "manifest_mismatch",
}

STATUS_MESSAGES = {
    "success": "Analysis completed.",
    "partial_success": "Analysis partially completed.",
    "no_hook": "No npm lifecycle hook was found.",
    "unsupported_language": "Unsupported lifecycle command form.",
    "parse_failure": "JavaScript parsing failed.",
    "extraction_failure": "Package artifact processing failed.",
    "analysis_error": "Analysis failed.",
    "timeout": "Analysis timed out.",
    "manifest_mismatch": "Manifest and artifact metadata do not match.",
}

BEHAVIOR_LABELS = {
    "ci_cd_targeting": "CI/CD environment targeting",
    "environment_access": "Environment access",
    "external_communication": "External communication",
    "command_execution": "Command execution",
    "obfuscation": "Obfuscation",
    "file_modification": "File modification",
}

REASON_LABELS = {
    "ci_cd_targeting": "CI/CD targeting",
    "environment_access": "Environment access",
    "external_communication": "External communication",
    "command_execution": "Command execution",
    "obfuscation": "Obfuscation",
    "file_modification": "File modification",
    "taint path": "Taint path",
    "webhook sink": "Webhook sink",
    "CI/CD secret source": "CI/CD secret source",
}

TOKEN_RE = re.compile(
    r"(?i)(token|secret|key|password|passwd|auth|signature|sig|credential)"
)


def terminal_status_from_raw(raw: dict[str, Any]) -> str:
    """raw analyzer 결과에서 사용자에게 보여줄 terminal status를 추론한다."""
    explicit = raw.get("terminal_status")
    if explicit:
        return str(explicit)
    hooks = raw.get("hooks_found") or []
    if not hooks:
        return "no_hook"
    return "success"


def priority_from_score(score: int | None, terminal_status: str) -> str:
    """기존 점수를 review-priority label로 매핑한다."""
    if terminal_status not in ANALYZABLE_STATUSES:
        return "unavailable"
    if score is None:
        return "unavailable"
    if score >= 200:
        return "high"
    if score >= 80:
        return "medium"
    return "low"


def risk_level_to_priority(raw_level: str | None, score: int | None, status: str) -> str:
    """analyzer threshold는 유지하되 악성 판정이 아닌 review-priority 언어로 표현한다."""
    if status not in ANALYZABLE_STATUSES:
        return "unavailable"
    if raw_level:
        level = str(raw_level).lower()
        if level in {"high", "medium", "low"}:
            return level
    return priority_from_score(score, status)


def build_user_summary(result: dict[str, Any]) -> dict[str, Any]:
    """raw/structured 결과를 사용자용 JSON 스키마로 변환한다.

    연구용 raw analyzer 출력과 사용자 출력 사이의 신뢰 경계다. 실패 상태를 보존하고,
    악성 판정 표현을 피하며, CI 연동에 필요한 안정 필드를 제공한다.
    """
    terminal_status = terminal_status_from_raw(result)
    final_score = _optional_int(result.get("final_score"))
    lifecycle_hooks = _lifecycle_hooks(result)
    entry_files = infer_entry_files(result)
    reachable_count = len(entry_files)
    if not reachable_count:
        reachable_count = int(result.get("reachable_file_count") or 0)
    behaviors = _behavior_labels(result)
    combos = _combo_reasons(result)
    taint_paths = list(result.get("taint_paths") or [])
    evidence = result.get("evidence") or {}
    taint_state = str(evidence.get("taint_evidence") or _taint_state(taint_paths, terminal_status))
    failures = list(result.get("analysis_failures") or [])
    if terminal_status in FAILURE_STATUSES and not failures:
        failures = [STATUS_MESSAGES.get(terminal_status, terminal_status)]
    priority = risk_level_to_priority(
        result.get("final_risk_level"),
        final_score,
        terminal_status,
    )
    review_targets = recommended_review_locations(result)
    score_explanation = aggregate_reasons(result)
    package_name = result.get("package")
    package_version = result.get("version")
    scope = {
        "entry_files": entry_files,
        "reachable_file_count": reachable_count,
        "failed_file_count": len(result.get("failed_files") or []),
        "path": result.get("path"),
    }

    return {
        "schema_version": "1.0",
        "tool_version": TOOL_VERSION,
        "engine_profile": ENGINE_PROFILE,
        "review_priority_model": REVIEW_PRIORITY_MODEL,
        "legacy_recorded_rule_hash": LEGACY_RECORDED_RULE_HASH,
        "legacy_hash_note": (
            "metadata-recorded identifier; not reproducible from currently "
            "reachable Git objects"
        ),
        "package": {
            "name": package_name,
            "version": package_version,
            "path": result.get("path"),
        },
        "analysis_status": {
            "status": terminal_status,
            "message": STATUS_MESSAGES.get(terminal_status, "Analysis status needs review."),
        },
        "review_priority": {
            "level": priority,
            "score": final_score,
            "is_malicious_verdict": False,
        },
        "hooks": lifecycle_hooks,
        "observed_behaviors": behaviors,
        "taint_summary": {
            "state": taint_state,
            "path_count": len(taint_paths),
        },
        "scope": scope,
        "review_targets": review_targets,
        "score_evidence": score_explanation,
        "limitations": [
            "High means review priority, not a malicious verdict.",
            "This preview does not claim byte-for-byte reproduction of legacy archived artifacts.",
            "Preview scoring includes CI/CD targeting signals that require separate validation.",
        ],
        "package_name": package_name,
        "version": package_version,
        "review_priority_label": priority,
        "is_malicious_prediction": False,
        "terminal_status": terminal_status,
        "status_message": STATUS_MESSAGES.get(terminal_status, "Analysis status needs review."),
        "lifecycle_hooks": lifecycle_hooks,
        "entry_files": entry_files,
        "reachable_file_count": reachable_count,
        "failed_file_count": scope["failed_file_count"],
        "behaviors": behaviors,
        "same_hook_scope_combos": combos,
        "taint_evidence": taint_state,
        "taint_path_count": len(taint_paths),
        "analysis_failures": failures,
        "recommended_review_locations": review_targets,
        "safe_next_actions": safe_next_actions(terminal_status),
        "final_score": final_score,
        "score_explanation": score_explanation,
    }


def render_summary(summary: dict[str, Any]) -> str:
    """기본 요약 출력을 만든다.

    이 요약은 자동 악성/정상 결정을 위한 것이 아니라, 사람이 어떤 파일과 라인을
    먼저 볼지 판단하도록 돕는 화면이다.
    """
    lines = [
        "npm-hook-risk",
        "",
        f"Package: {_package_label(summary)}",
        f"Engine profile: {summary.get('engine_profile', ENGINE_PROFILE)}",
        f"Review priority model: {summary.get('review_priority_model', REVIEW_PRIORITY_MODEL)}",
        f"Review priority: {_title(_priority_label(summary))}",
        "Malicious verdict: Not provided",
        f"Analysis status: {summary.get('status_message', summary['terminal_status'])}",
        "",
        "Lifecycle hooks:",
    ]
    hooks = summary.get("lifecycle_hooks") or []
    lines.extend(
        f"- {hook['hook']}: {hook['command']}" for hook in hooks
    )
    if not hooks:
        lines.append("- none")

    lines.extend(["", "Observed behaviors:"])
    behaviors = summary.get("behaviors") or []
    lines.extend(f"- {item}" for item in behaviors) if behaviors else lines.append("- none")

    taint_count = summary.get("taint_path_count", 0)
    lines.extend(["", "Taint evidence:"])
    if taint_count:
        lines.append(f"- {taint_count} source-to-sink paths")
        sinks = _unique_sinks(summary)
        if sinks:
            lines.append(f"- Sink: {', '.join(sinks)}")
    else:
        lines.append(f"- {summary.get('taint_evidence', 'unavailable')}")

    locations = summary.get("recommended_review_locations") or []
    review_lines = _line_set(locations)
    lines.extend(
        [
            "",
            "Analysis scope:",
            f"- Entry files: {len(summary.get('entry_files') or [])}",
            f"- Reachable local JS files: {summary.get('reachable_file_count', 0)}",
            f"- Failed files: {summary.get('failed_file_count', 0)}",
        ]
    )
    if summary.get("entry_files"):
        lines.append(f"- Main file: {summary['entry_files'][0]}")
    if review_lines:
        lines.append(f"- Review lines: {review_lines}")

    lines.extend(["", "Why this priority:"])
    score_items = summary.get("score_explanation") or []
    lines.extend(f"- {item['label']}: {item['text']}" for item in score_items)
    if not score_items:
        lines.append("- No score-bearing evidence was reported.")

    lines.extend(
        [
            "",
            "Important:",
            "High means review priority, not a malicious verdict.",
        ]
    )
    return "\n".join(lines)


def render_explain(raw: dict[str, Any], summary: dict[str, Any]) -> str:
    """Render detailed evidence without source dumps or unredacted secrets."""
    lines = [render_summary(summary), "", "Detailed evidence:"]
    for hook_name, hook in (raw.get("hooks") or {}).items():
        lines.append(f"")
        lines.append(f"Hook: {hook_name}")
        lines.append(f"- Command: {hook.get('command')}")
        categories = hook.get("categories") or []
        lines.append("- Categories:")
        if categories:
            for category in categories:
                label = BEHAVIOR_LABELS.get(category, category)
                patterns = hook.get("matched_patterns", {}).get(category, [])
                redacted = ", ".join(redact(str(pattern)) for pattern in patterns)
                lines.append(f"  - {label}: {redacted}")
        else:
            lines.append("  - none")

        combo_lines = [
            item for item in aggregate_reasons({"hooks": {hook_name: hook}})
            if item["kind"] == "combo"
        ]
        lines.append("- Same-hook combinations:")
        if combo_lines:
            lines.extend(f"  - {item['label']}: {item['text']}" for item in combo_lines)
        else:
            lines.append("  - none")

        paths = hook.get("taint_paths") or []
        lines.append("- Taint paths:")
        if not paths:
            lines.append("  - none")
        for index, path in enumerate(paths, 1):
            source = path.get("source", {})
            sink = path.get("sink", {})
            lines.append(
                f"  - Path {index}: {source.get('type')} at "
                f"{source.get('file')}:{source.get('line')} -> "
                f"{sink.get('type')} at {sink.get('file')}:{sink.get('line')}"
            )
            if source.get("expression"):
                lines.append(f"    source: {redact(str(source['expression']))}")
            if sink.get("webhook_url"):
                lines.append(f"    sink url: {redact_url(str(sink['webhook_url']))}")
            propagation = path.get("propagation") or []
            if propagation:
                last = propagation[-1]
                lines.append(
                    "    propagation: "
                    f"{len(propagation)} steps, ending at line {last.get('line')}"
                )

    profile = raw.get("analysis_profile") or {}
    parser = profile.get("parser_provenance") or {}
    if parser or raw.get("parser_used"):
        lines.extend(["", "Parser provenance:"])
        lines.append(f"- parser_used: {raw.get('parser_used') or parser.get('parser_used')}")
        lines.append(f"- parser_primary: {raw.get('parser_primary') or parser.get('parser_primary')}")
        fallback = raw.get("parser_fallback") or parser.get("parser_fallback")
        if fallback:
            lines.append(f"- parser_fallback: {fallback}")

    failures = summary.get("analysis_failures") or []
    if failures:
        lines.extend(["", "Failures / unsupported status:"])
        lines.extend(f"- {failure}" for failure in failures)
    return "\n".join(lines)


def aggregate_reasons(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Group repeated score reasons without changing raw scoring."""
    reasons: list[str] = []
    for hook in (result.get("hooks") or {}).values():
        reasons.extend(str(item) for item in hook.get("reasons", []))

    grouped: dict[tuple[str, int, str], int] = defaultdict(int)
    order: list[tuple[str, int, str]] = []
    for reason in reasons:
        parsed = _parse_reason(reason)
        if parsed is None:
            continue
        key = parsed
        if key not in grouped:
            order.append(key)
        grouped[key] += 1

    items = []
    total = 0
    for name, points, kind in order:
        count = grouped[(name, points, kind)]
        subtotal = count * points
        total += subtotal
        label = _reason_label(name)
        text = f"+{points}" if count == 1 else f"{count} x {points} = {subtotal}"
        items.append(
            {
                "kind": kind,
                "label": label,
                "count": count,
                "points_each": points,
                "points_total": subtotal,
                "text": text,
            }
        )
    final_score = _optional_int(result.get("final_score"))
    if final_score is not None and total != final_score:
        items.append(
            {
                "kind": "warning",
                "label": "Score explanation warning",
                "count": 1,
                "points_each": 0,
                "points_total": 0,
                "text": f"grouped reasons sum to {total}, final score is {final_score}",
            }
        )
    return items


def recommended_review_locations(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Return deduplicated file/line review hints."""
    seen: set[tuple[str, int | None, str]] = set()
    locations: list[dict[str, Any]] = []
    for path in result.get("taint_paths") or []:
        for part_name in ("source", "sink"):
            part = path.get(part_name, {})
            file_name = part.get("file")
            if not file_name:
                continue
            line = _optional_int(part.get("line"))
            reason = str(part.get("type") or part_name)
            key = (str(file_name), line, reason)
            if key in seen:
                continue
            seen.add(key)
            locations.append({"file": str(file_name), "line": line, "reason": reason})
    for file_name in infer_entry_files(result):
        key = (file_name, None, "lifecycle entry file")
        if key not in seen:
            seen.add(key)
            locations.append({"file": file_name, "line": None, "reason": "lifecycle entry file"})
    return locations


def infer_entry_files(result: dict[str, Any]) -> list[str]:
    """Infer files actually analyzed without changing raw analyzer semantics."""
    files: list[str] = []
    files.extend(str(path) for path in result.get("reachable_files") or [])
    for path in result.get("taint_paths") or []:
        for part in ("source", "sink"):
            file_name = path.get(part, {}).get("file")
            if file_name:
                files.append(str(file_name).replace("\\", "/"))
    for hook in (result.get("hooks") or {}).values():
        command = str(hook.get("command") or "")
        for token in re.findall(r"(?:\./)?[A-Za-z0-9_./@-]+\.(?:c|m)?js\b", command):
            files.append(token.removeprefix("./").replace("\\", "/"))
    return sorted(dict.fromkeys(files))


def safe_next_actions(terminal_status: str) -> list[str]:
    if terminal_status == "success":
        return ["Review the listed evidence and files before installing in CI."]
    if terminal_status == "partial_success":
        return ["Review evidence and separately inspect failed files or stages."]
    if terminal_status == "no_hook":
        return ["No lifecycle-hook-specific review is required."]
    if terminal_status == "unsupported_language":
        return ["Manually inspect the shell/native command and invoked files."]
    return ["Do not treat this as low risk; inspect the failure status and provenance."]


def redact(text: str) -> str:
    """Mask token-like material in short expressions."""
    redacted = re.sub(
        r"(?i)(token|secret|password|passwd|key|auth)(['\"]?\s*[:=]\s*['\"]?)[^'\"\s,}]+",
        r"\1\2<redacted>",
        text,
    )
    redacted = re.sub(r"(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+", r"\1<redacted>", redacted)
    return redacted


def redact_url(url: str) -> str:
    """Show URL provenance while masking token-like path/query material."""
    parsed = urlsplit(url)
    path_parts = [part for part in parsed.path.split("/") if part]
    safe_parts: list[str] = []
    webhook_seen = False
    for part in path_parts[:3]:
        if webhook_seen or TOKEN_RE.search(part) or re.fullmatch(r"[A-Za-z0-9_-]{10,}", part):
            safe_parts.append("<redacted>")
        else:
            safe_parts.append(part)
        if part.lower() == "webhooks":
            webhook_seen = True
    if len(path_parts) > 3:
        safe_parts.append("...")
    safe_path = "/" + "/".join(safe_parts) if safe_parts else ""
    query = ""
    if parsed.query:
        query = "<redacted>"
    return urlunsplit((parsed.scheme, parsed.netloc, safe_path, query, ""))


def _lifecycle_hooks(result: dict[str, Any]) -> list[dict[str, str]]:
    structured = result.get("lifecycle_hooks")
    if isinstance(structured, list):
        return [
            {"hook": str(item.get("hook")), "command": str(item.get("command"))}
            for item in structured
            if isinstance(item, dict)
        ]
    hooks = result.get("hooks") or {}
    return [
        {"hook": str(name), "command": str(data.get("command") or "")}
        for name, data in hooks.items()
    ]


def _behavior_labels(result: dict[str, Any]) -> list[str]:
    categories: list[str] = []
    for hook in (result.get("hooks") or {}).values():
        categories.extend(str(category) for category in hook.get("categories", []))
    if not categories:
        evidence = result.get("evidence") or {}
        categories.extend(str(item) for item in evidence.get("behaviors", []))
    return [BEHAVIOR_LABELS.get(item, item) for item in sorted(dict.fromkeys(categories))]


def _combo_reasons(result: dict[str, Any]) -> list[str]:
    combos = []
    for item in aggregate_reasons(result):
        if item["kind"] == "combo":
            combos.append(item["label"])
    if not combos:
        evidence = result.get("evidence") or {}
        combos.extend(str(item) for item in evidence.get("same_hook_scope_combos", []))
    return combos


def _parse_reason(reason: str) -> tuple[str, int, str] | None:
    combo = re.match(r"combo\((.+)\): \+(\d+)$", reason)
    if combo:
        return combo.group(1), int(combo.group(2)), "combo"
    normal = re.match(r"(.+): \+(\d+)$", reason)
    if normal:
        name = normal.group(1)
        kind = "taint" if name in {"taint path", "webhook sink", "CI/CD secret source"} else "category"
        return name, int(normal.group(2)), kind
    return None


def _reason_label(name: str) -> str:
    if name in REASON_LABELS:
        return REASON_LABELS[name]
    if " + " in name:
        return " + ".join(_reason_label(part) for part in name.split(" + "))
    return name.replace("_", " ").title()


def _taint_state(paths: list[dict[str, Any]], status: str) -> str:
    if paths:
        return "present"
    # Structured test/user-summary inputs may already provide the state.
    # The caller passes only paths/status, so this fallback is handled in
    # build_user_summary by leaving raw analyzer paths empty.
    if status in ANALYZABLE_STATUSES or status == "no_hook":
        return "absent"
    return "unavailable"


def _optional_int(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _package_label(summary: dict[str, Any]) -> str:
    package_payload = summary.get("package")
    if isinstance(package_payload, dict):
        package = package_payload.get("name") or "(unknown)"
        version = package_payload.get("version")
    else:
        package = package_payload or summary.get("package_name") or "(unknown)"
        version = summary.get("version")
    return f"{package}@{version}" if version else str(package)


def _priority_label(summary: dict[str, Any]) -> str:
    priority = summary.get("review_priority")
    if isinstance(priority, dict):
        return str(priority.get("level") or "unavailable")
    return str(priority or summary.get("review_priority_label") or "unavailable")


def _title(value: Any) -> str:
    return str(value or "unavailable").replace("_", " ").title()


def _unique_sinks(summary: dict[str, Any]) -> list[str]:
    sinks = []
    for location in summary.get("recommended_review_locations") or []:
        if "webhook" in location.get("reason", ""):
            sinks.append("Webhook sink")
    return sorted(set(sinks))


def _line_set(locations: list[dict[str, Any]]) -> str:
    by_file: dict[str, list[int]] = defaultdict(list)
    for location in locations:
        line = location.get("line")
        if isinstance(line, int):
            by_file[str(location.get("file"))].append(line)
    parts = []
    for file_name, lines in sorted(by_file.items()):
        unique = sorted(set(lines))
        parts.append(f"{file_name}:{', '.join(map(str, unique))}")
    return "; ".join(parts)
