"""install-hook taint 분석용 source/sink 선언형 룰.

source는 민감 정보가 시작되는 위치, sink는 외부로 나가거나 시스템에 영향을 주는
위치다. 이 목록은 사람이 검토할 근거를 만들기 위한 규칙이며 악성 판정표가 아니다.
"""

# 민감 정보가 시작되는 지점: 환경 변수, CI/CD secret, 민감 파일 읽기 등.
SOURCES = {
    "environment_access": {
        "member_patterns": [
            r"^process\.env(\..*)?$",
        ],
        "call_names": [
            "os.userInfo",
        ],
    },
    "command_execution": {
        "call_names": ["execSync", "exec", "spawn", "spawnSync", "execFile"],
        "require_modules": ["child_process"],
    },
    "sensitive_file_read": {
        "call_names": ["fs.readFileSync", "fs.readFile", "fsp.readFile"],
        "literal_path_patterns": [
            r"^/etc/(passwd|shadow|hosts)",
            r"\.ssh/",
            r"\.aws/credentials",
            r"\.npmrc",
            r"\.bash_history",
            r"\.zsh_history",
        ],
    },
    "ci_cd_secrets": {
        "member_patterns": [
            r"^process\.env\.(GITHUB_TOKEN|AWS_ACCESS_KEY_ID|NPM_TOKEN|VAULT_TOKEN)$",
            r"^process\.env\.(GITHUB_ACTIONS|CI|RUNNER_OS)$",
        ],
    },
}

# 민감 정보가 도달하면 검토 가치가 높은 지점: 외부 통신, 명령 실행, 파일 쓰기 등.
SINKS = {
    "external_communication": {
        "call_names": [
            "fetch",
            "https.request",
            "http.request",
            "https.get",
            "http.get",
            "axios.post",
            "axios.get",
            "net.connect",
            "net.createConnection",
        ],
    },
    "command_execution_sink": {
        "call_names": ["execSync", "exec", "spawn", "spawnSync"],
    },
    "file_write_sink": {
        "call_names": [
            "fs.writeFileSync",
            "fs.writeFile",
            "fs.appendFileSync",
        ],
    },
    "webhook_url": {
        "argument_literal_patterns": [
            r"discord(?:app)?\.com/api/webhooks",
            r"hooks\.slack\.com/services",
            r"api\.telegram\.org/bot\d+",
            r"webhook\.site/",
            # OOB callback 서비스: 실제 사례에서 관찰된 외부 수신/콜백 인프라.
            r"\.oastify\.com",
            r"\.oast\.(?:fun|pro|me|live|site|online)",
            r"\.requestbin\.com",
            r"\.beeceptor\.com",
            r"\.pipedream\.net",
            r"\.ngrok\.io",
            r"\.serveo\.net",
            r"\.loca\.lt",
        ],
    },
}
