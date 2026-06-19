#!/usr/bin/env python3
"""npm lifecycle hook 정적 분석의 핵심 엔진.

패키지 설치 스크립트를 실행하지 않고 package.json의 preinstall/install/
postinstall 훅과 도달 가능한 로컬 JavaScript만 읽어 review-priority 근거를
계산한다. 이 점수는 악성 판정이 아니라 사람이 먼저 볼 순서를 정하기 위한
트리아지 신호다.
"""
import base64
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from taint_analyzer import analyze_source
    from ast_utils import MAX_JS_BYTES
except ImportError:
    from tools.taint_analyzer import analyze_source
    from tools.ast_utils import MAX_JS_BYTES

# npm 설치 중 자동 실행될 수 있는 lifecycle hook만 분석 범위로 둔다.
HOOKS = ["preinstall", "install", "postinstall"]
CATEGORY_ORDER = [
    "ci_cd_targeting",
    "environment_access",
    "external_communication",
    "command_execution",
    "obfuscation",
    "file_modification",
]

# 정규식 룰은 빠른 1차 근거 수집용이다. 최종 해석은 taint path와 함께 본다.
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
    "ci_cd_targeting": [
        r"\bGITHUB_TOKEN\b",
        r"\bGITHUB_ACTIONS\b",
        r"\bRUNNER_OS\b",
        r"\bCI\b(?!\w)",
        r"\bJENKINS_URL\b",
        r"\bGITLAB_CI\b",
        r"\bCIRCLECI\b",
        r"\bAWS_ACCESS_KEY_ID\b",
        r"\bAWS_SECRET_ACCESS_KEY\b",
        r"\bAWS_SESSION_TOKEN\b",
        r"\bGOOGLE_APPLICATION_CREDENTIALS\b",
        r"\bAZURE_CLIENT_SECRET\b",
        r"\bNPM_TOKEN\b",
        r"\bnpm_config_.*token\b",
        r"\bVAULT_TOKEN\b",
        r"\bKUBE.*TOKEN\b",
        r"\.aws[/\\]credentials",
        r"\.docker[/\\]config\.json",
        r"\.npmrc",
        r"\.kube[/\\]config",
        r"\.config[/\\]gcloud",
        r"id_rsa\b",
        r"id_ed25519\b",
        r"\.ssh[/\\]",
        r"aws\s+sts\s+get-caller-identity",
        r"aws\s+s3\s+(cp|sync|ls)",
        r"gcloud\s+auth",
        r"kubectl\s+(get|describe)\s+secret",
        r"vault\s+(read|kv)",
        r"gh\s+auth\s+token",
    ],
}

# 가중치는 공개 preview의 review-priority 모델이다. 악성/정상 분류 임계값이 아니다.
WEIGHTS = {
    "environment_access": 15,
    "external_communication": 15,
    "command_execution": 25,
    "obfuscation": 20,
    "file_modification": 15,
    "ci_cd_targeting": 20,
}

# 복합 행위는 단일 신호보다 검토 우선순위를 높이는 보조 근거로만 사용한다.
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
    (
        {"ci_cd_targeting", "external_communication"},
        50,
        "CI/CD targeting + external communication",
    ),
    (
        {"ci_cd_targeting", "obfuscation"},
        40,
        "CI/CD targeting + obfuscation",
    ),
    (
        {"ci_cd_targeting", "external_communication", "obfuscation"},
        30,
        "CI/CD targeting + external communication + obfuscation",
    ),
]


# ── 난독화 해제 ──────────────────────────────────────────────────

def deobfuscate(text: str) -> tuple[str, list[str]]:
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

def read_package_json(package_dir: Path) -> dict[str, Any]:
    """Read and parse package.json from a package directory."""
    package_json = package_dir / "package.json"
    if not package_json.exists():
        raise FileNotFoundError(f"package.json not found: {package_json}")
    return json.loads(package_json.read_text(encoding="utf-8"))


def collect_hook_sources(
    package_dir: Path,
    scripts: dict[str, Any],
    reachable_files: list[Path] | None = None,
    expanded_scripts: dict[str, list[str]] | None = None,
) -> dict[str, str]:
    """Lifecycle command와 hook에서 도달 가능한 JS 파일 내용을 모은다."""
    sources: dict[str, str] = {}
    # 연구용 canonical run에서는 adapter가 넘긴 reachable_files만 사용한다.
    # fallback으로 package 전체를 훑으면 논문 실험의 스코프가 깨진다.
    canonical_files = list(reachable_files or [])
    for hook in HOOKS:
        command = scripts.get(hook)
        if not command:
            continue
        commands = (
            expanded_scripts.get(hook, [command])
            if expanded_scripts is not None
            else [command]
        )
        text = "\n".join(commands) + "\n"
        if canonical_files:
            hook_paths = canonical_files
        else:
            hook_paths = []
            for token in command.split():
                if token.endswith(".js"):
                    js_path = package_dir / token
                    if js_path.exists():
                        hook_paths.append(js_path)
        for js_path in hook_paths:
            text += "\n" + js_path.read_text(encoding="utf-8", errors="ignore")
        sources[hook] = text
    return sources


def collect_hook_files(
    package_dir: Path,
    scripts: dict[str, Any],
    reachable_files: list[Path] | None = None,
) -> dict[str, list[Path]]:
    """각 hook에서 직접 참조된 기존 JavaScript 파일 목록을 수집한다."""
    hook_files: dict[str, list[Path]] = {}
    for hook in HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str):
            continue
        if reachable_files is not None:
            hook_files[hook] = list(reachable_files)
            continue
        files: list[Path] = []
        for token in re.findall(r"(?:\./)?[A-Za-z0-9_./@-]+\.m?js\b", command):
            relative = Path(token.removeprefix("./"))
            if relative.is_absolute() or ".." in relative.parts:
                continue
            path = package_dir / relative
            if path.is_file():
                files.append(path)
        hook_files[hook] = files
    return hook_files


def score_taint_paths(paths: list[dict[str, Any]]) -> tuple[int, list[str]]:
    """source-to-sink taint path를 별도 점수와 사람이 읽을 이유로 변환한다."""
    score = 0
    reasons: list[str] = []
    for path in paths:
        score += 40
        reasons.append("taint path: +40")
        if path["source"]["type"] == "ci_cd_secrets":
            score += 20
            reasons.append("CI/CD secret source: +20")
        if path["sink"]["type"] == "webhook_url":
            score += 20
            reasons.append("webhook sink: +20")
    return score, reasons


def analyze_text(text: str) -> tuple[dict[str, list[str]], list[str]]:
    """원문과 단순 복호화 텍스트에서 행위 카테고리 근거를 찾는다."""
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

    ordered = {
        category: detected[category]
        for category in CATEGORY_ORDER
        if category in detected
    }
    return ordered, deobf_findings


def score_categories(
    categories: dict[str, list[str]],
) -> tuple[int, str, list[str]]:
    """탐지된 카테고리와 복합 행위를 review-priority 점수로 합산한다."""
    detected = set(categories.keys())
    score = 0
    reasons = []
    for cat in CATEGORY_ORDER:
        if cat not in detected:
            continue
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


def analyze_package_dir(
    package_dir: Path,
    reachable_files: list[Path] | None = None,
    expanded_scripts: dict[str, list[str]] | None = None,
) -> dict[str, Any]:
    """압축 해제된 npm 패키지 하나를 정적으로 분석한다."""
    package_dir = package_dir.resolve()
    pkg = read_package_json(package_dir)
    scripts = pkg.get("scripts", {})
    # reachable_files가 주어지면 canonical hook-scope 분석이다.
    # None이면 공개 CLI의 단순 직접 참조 방식으로 동작한다.
    canonical_files = (
        [Path(path).resolve() for path in reachable_files]
        if reachable_files is not None
        else None
    )
    hook_sources = collect_hook_sources(
        package_dir,
        scripts,
        reachable_files=canonical_files,
        expanded_scripts=expanded_scripts,
    )
    hook_files = collect_hook_files(
        package_dir,
        scripts,
        reachable_files=canonical_files,
    )

    result = {
        "package": pkg.get("name"),
        "version": pkg.get("version"),
        "path": str(package_dir),
        "hooks_found": list(hook_sources.keys()),
        "hooks": {},
        "taint_paths": [],
        "taint_path_count": 0,
        "reachable_files": [
            path.relative_to(package_dir).as_posix()
            for path in canonical_files or []
        ],
        "final_score": 0,
        "final_risk_level": "Low",
    }

    max_score = 0
    max_level = "Low"

    for hook, source_text in hook_sources.items():
        # 1) 정규식 기반 행위 근거, 2) AST 기반 taint path를 분리해서 수집한다.
        categories, deobf_findings = analyze_text(source_text)
        score, level, reasons = score_categories(categories)
        taint_paths: list[dict[str, Any]] = []
        for js_path in hook_files.get(hook, []):
            if js_path.stat().st_size > MAX_JS_BYTES:
                continue
            source = js_path.read_text(encoding="utf-8", errors="ignore")
            taint_paths.extend(
                path.to_dict()
                for path in analyze_source(
                    source,
                    str(js_path.relative_to(package_dir)).replace("\\", "/"),
                )
            )
        taint_score, taint_reasons = score_taint_paths(taint_paths)
        score += taint_score
        reasons.extend(taint_reasons)
        if score >= 60:
            level = "High"
        elif score >= 30:
            level = "Medium"
        else:
            level = "Low"

        result["hooks"][hook] = {
            "command": scripts.get(hook),
            "categories": list(categories.keys()),
            "matched_patterns": {
                k: v for k, v in categories.items()
            },
            "deobfuscation_findings": deobf_findings,
            "taint_paths": taint_paths,
            "taint_path_count": len(taint_paths),
            "score": score,
            "risk_level": level,
            "reasons": reasons,
        }
        result["taint_paths"].extend(taint_paths)

        if score > max_score:
            max_score = score
            max_level = level

    result["final_score"] = max_score
    result["final_risk_level"] = max_level
    result["taint_path_count"] = len(result["taint_paths"])

    # 제품형 preview는 npm lifecycle hook triage에 집중한다.

    return result


def main() -> None:
    """Run the single-package analyzer command-line interface."""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <package_dir>", file=sys.stderr)
        sys.exit(1)

    result = analyze_package_dir(Path(sys.argv[1]))
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
