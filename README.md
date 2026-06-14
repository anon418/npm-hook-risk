# npm-hook-risk

NPM 패키지의 install lifecycle hook(preinstall/install/postinstall)에서
악성 행위 패턴을 설치 전에 정적 분석하는 경량 도구.

## 왜 필요한가

`npm audit`는 CVE 기반이라 알려지지 않은 악성 install script를 탐지하지 못한다.
실제 사례: `amplitude-ma-ts`는 npm audit 경고 없이 설치 시 시스템 정보를
외부 서버로 전송하는 코드를 postinstall에 포함하고 있었다.

## 사용법

```bash
# 단일 패키지 분석
python3 tools/analyze_package.py ./my-package

# package.json 의존성 전체 스캔
python3 tools/scan_deps.py ./package.json
```

## 탐지 카테고리

| Category | 예시 패턴 |
|---|---|
| environment_access | process.env, AWS_ACCESS_KEY_ID |
| external_communication | https://, curl, wget |
| command_execution | child_process, exec, spawn |
| obfuscation | base64, eval, Buffer.from |
| file_modification | fs.writeFile, chmod, .npmrc |

## 기존 도구와 비교

| 도구 | Install hook 분석 | 탐지 근거 | 오픈소스 |
|---|---|---|---|
| npm audit | ❌ | ❌ | ✅ |
| Socket.dev | ✅ | ❌ | ❌ |
| 이 도구 | ✅ | ✅ | ✅ |

## 실험 결과

- benign 133개: FP Rate 3.0%
- baseline 대비 오탐 50% 감소
- 실제 악성 패키지 amplitude-ma-ts score 100, High 탐지

## 논문

한국정보보호학회 투고 예정
