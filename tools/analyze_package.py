#!/usr/bin/env python3
"""
npm-hook-risk: NPM Install Lifecycle Hook Risk Analyzer
Usage: python3 analyze_package.py <package_dir>
"""
import base64
import json
import re
import sys
from pathlib import Path

HOOKS = ["preinstall", "install", "postinstall"]

RULES = {
    "environment_access": [
        r"process\.env",
        r"os\.userInfo",
        r"HOME",
        r"USERPROFILE",
        r"NPM_TOKEN",
        r"npm_config",
        r"AWS_ACCESS_KEY_ID",
        r"AWS_SECRET_ACCESS_KEY",
        r"GITHUB_TOKEN",
        r"GITHUB_ACTIONS",
        r"process\.env\.CI",
    ],
    "external_communication": [
        r"https?://",
        r"\bcurl\b",
        r"\bwget\b",
        r"fetch\s*\(",
        r"https\.request",
        r"http\.request",
    ],
    "command_execution": [
        r"child_process",
        r"\bexec\s*\(",
        r"\bspawn\s*\(",
        r"(^|[\s;&|])bash(\s|$)",
        r"(^|[\s;&|])sh(\s|$)",
        r"powershell",
        r"cmd\.exe",
    ],
    "obfuscation": [
        r"\beval\s*\(",
        r"Function\s*\(",
        r"base64",
        r"Buffer\.from",
    ],
    "file_modification": [
        r"fs\.writeFile",
        r"fs\.appendFile",
        r"chmod",
        r"\brm\s+",
        r"\.npmrc",
        r"\.bashrc",
        r"\.profile",
    ],
}

WEIGHTS = {
    "environment_access": 15,
    "external_communication": 15,
    "command_execution": 25,
    "obfuscation": 20,
    "file_modification": 15,
}

COMBO_WEIGHTS = [
    (
        {"environment_access", "external_communication"},
        20,
        "environment access + external communication",
    ),
    (
        {"external_communication", "command_execution"},
        25,
        "external communication + command execution",
    ),
    (
        {"obfuscation", "command_execution"},
        25,
        "obfuscation + command execution",
    ),
]


# ── 난독화 해제 ──────────────────────────────────────────────────

def deobfuscate(text: str) -> tuple[str, list]:
    """
    난독화된 텍스트를 디코딩하여 추가 분석 텍스트와 탐지 근거를 반환.
    실제 실행 없이 텍스트 변환만 수행.
    """
    extra = ""
    findings = []

    # 1. base64 디코딩 후 재분석
    b64_pattern = re.findall(r'["\`]([A-Za-z0-9+/]{20,}={0,2})["\`]', text)
    for m in b64_pattern:
        try:
            decoded = base64.b64decode(m).decode("utf-8", errors="ignore")
            # 의미 있는 텍스트인지 확인 (알파벳 비율 40% 이상)
            alpha_ratio = sum(c.isalpha() for c in decoded) / max(len(decoded), 1)
            if alpha_ratio > 0.4:
                extra += "\n" + decoded
                findings.append(f"base64 decoded: {decoded[:60]}...")
        except Exception:
            pass

    # 2. 문자열 연결 난독화 ("ev"+"al", 'ex'+'ec' 형태)
    concat_pattern = re.findall(
        r'["\']([a-zA-Z]{1,8})["\']\s*\+\s*["\']([a-zA-Z]{1,8})["\']', text
    )
    for a, b in concat_pattern:
        combined = a + b
        extra += "\n" + combined
        # 위험 키워드와 매칭되는지 확인
        danger = ["eval", "exec", "spawn", "require", "system", "shell"]
        if any(d in combined.lower() for d in danger):
            findings.append(f"string concat obfuscation: '{a}'+'{b}' -> '{combined}'")

    # 3. hex 이스케이프 디코딩 (\x65\x76\x61\x6c 형태)
    hex_pattern = re.findall(r'((?:\\x[0-9a-fA-F]{2}){4,})', text)
    for h in hex_pattern:
        try:
            decoded = bytes.fromhex(h.replace("\\x", "")).decode("utf-8", errors="ignore")
            extra += "\n" + decoded
            findings.append(f"hex decoded: {decoded[:60]}")
        except Exception:
            pass

    # 4. unicode 이스케이프 (\u0065\u0076\u0061\u006c 형태)
    uni_pattern = re.findall(r'((?:\\u[0-9a-fA-F]{4}){3,})', text)
    for u in uni_pattern:
        try:
            decoded = u.encode("utf-8").decode("unicode_escape", errors="ignore")
            extra += "\n" + decoded
            findings.append(f"unicode decoded: {decoded[:60]}")
        except Exception:
            pass

    # 5. Buffer.from(..., 'hex') 패턴
    buf_hex = re.findall(r"Buffer\.from\(['\"]([0-9a-fA-F]{10,})['\"],\s*['\"]hex['\"]", text)
    for h in buf_hex:
        try:
            decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
            extra += "\n" + decoded
            findings.append(f"Buffer.from hex decoded: {decoded[:60]}")
        except Exception:
            pass

    return extra, findings


# ── 핵심 분석 로직 ───────────────────────────────────────────────

def read_package_json(package_dir: Path):
    package_json = package_dir / "package.json"
    if not package_json.exists():
        raise FileNotFoundError(f"package.json not found: {package_json}")
    return json.loads(package_json.read_text(encoding="utf-8"))


def collect_hook_sources(package_dir: Path, scripts: dict):
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
                    text += "\n" + js_path.read_text(encoding="utf-8", errors="ignore")
        sources[hook] = text
    return sources


def analyze_text(text: str):
    # 원본 텍스트 분석
    detected = {}
    for category, patterns in RULES.items():
        matches = [p for p in patterns if re.search(p, text, re.IGNORECASE)]
        if matches:
            detected[category] = matches

    # 난독화 해제 후 추가 분석
    extra_text, deobf_findings = deobfuscate(text)
    if extra_text:
        for category, patterns in RULES.items():
            extra_matches = [
                p for p in patterns
                if re.search(p, extra_text, re.IGNORECASE)
                and p not in detected.get(category, [])
            ]
            if extra_matches:
                if category not in detected:
                    detected[category] = []
                detected[category].extend(
                    [f"[deobfuscated] {p}" for p in extra_matches]
                )

    return detected, deobf_findings


def score_categories(categories):
    detected = set(categories.keys())
    score = 0
    reasons = []
    for cat in sorted(detected):
        w = WEIGHTS.get(cat, 0)
        score += w
        reasons.append(f"{cat}: +{w}")
    for required, w, desc in COMBO_WEIGHTS:
        if required.issubset(detected):
            score += w
            reasons.append(f"combo({desc}): +{w}")
    if score >= 60:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"
    return score, level, reasons


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <package_dir>", file=sys.stderr)
        sys.exit(1)

    package_dir = Path(sys.argv[1]).resolve()
    pkg = read_package_json(package_dir)
    scripts = pkg.get("scripts", {})
    hook_sources = collect_hook_sources(package_dir, scripts)

    result = {
        "package": pkg.get("name"),
        "version": pkg.get("version"),
        "path": str(package_dir),
        "hooks_found": list(hook_sources.keys()),
        "hooks": {},
        "final_score": 0,
        "final_risk_level": "Low",
    }

    max_score = 0
    max_level = "Low"

    for hook, source_text in hook_sources.items():
        categories, deobf_findings = analyze_text(source_text)
        score, level, reasons = score_categories(categories)

        result["hooks"][hook] = {
            "command": scripts.get(hook),
            "categories": list(categories.keys()),
            "matched_patterns": {
                k: v for k, v in categories.items()
            },
            "deobfuscation_findings": deobf_findings,
            "score": score,
            "risk_level": level,
            "reasons": reasons,
        }

        if score > max_score:
            max_score = score
            max_level = level

    result["final_score"] = max_score
    result["final_risk_level"] = max_level

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
