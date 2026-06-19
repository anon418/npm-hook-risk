# npm-hook-risk 운영 가이드 (한국어)

`npm-hook-risk`는 npm `preinstall`, `install`, `postinstall` lifecycle hook을
정적으로 살펴보고 보안 담당자가 먼저 확인할 파일과 근거를 줄여 주는
review-priority triage 도구입니다. 패키지 스크립트를 실행하지 않으며,
악성/정상 판정을 제공하지 않습니다.

## 언제 쓰나

- 새 npm 패키지나 특정 버전을 설치하기 전에 lifecycle hook이 있는지 확인할 때
- CI에서 High review priority 또는 분석 실패 상태를 별도 검토로 넘기고 싶을 때
- `postinstall.js`처럼 설치 중 실행되는 로컬 JavaScript 파일의 행위 근거를 빠르게 보고 싶을 때
- 외부 통신, 명령 실행, 환경 변수 접근, 파일 쓰기, 난독화 흔적을 사람이 검토할 단서로 모으고 싶을 때

## 기본 사용 흐름

```powershell
npm-hook-risk scan .
npm-hook-risk scan . --details
npm-hook-risk scan package@1.2.3
npm-hook-risk scan @scope/package@1.2.3 --json --output summary.json
```

권장 흐름은 다음과 같습니다.

1. 기본 요약으로 hook 존재 여부와 review priority를 확인합니다.
2. Medium/High 또는 `partial_success`, `unsupported_language`, `parse_failure`가 나오면 `--details`로 다시 봅니다.
3. 출력된 파일, 라인, behavior, taint path를 사람이 직접 검토합니다.
4. 실패/미지원 상태를 Low 또는 안전한 패키지로 해석하지 않습니다.

## 출력 해석

- `High`: 먼저 검토해야 한다는 뜻입니다. 악성 판정이 아닙니다.
- `Medium`/`Low`: 정적 근거 기준의 우선순위입니다. 설치 승인이나 안전 보장이 아닙니다.
- `Unavailable`: 분석이 완료되지 않았거나 이 preview가 다루지 않는 command form입니다.
- `unsupported_language`: shell/native build/임의 interpreter 등 현재 preview 범위 밖의 hook입니다.
- `parse_failure`/`analysis_error`/`timeout`: 분석 실패 상태입니다. 안전하다는 뜻이 아닙니다.

## CI에서 쓰기

`--strict`를 사용하면 High review priority 또는 실패 상태에서 non-zero exit code를 반환합니다.

```powershell
npm-hook-risk scan package@1.2.3 --json --output npm-hook-risk.json --strict
```

Exit code는 README의 `JSON and CI` 섹션을 기준으로 해석하세요. CI에서는 이 도구의 결과를
자동 차단 verdict로 쓰기보다, 보안 리뷰 티켓 생성이나 수동 승인 단계로 연결하는 방식을 권장합니다.

## 한계

- 이 preview는 모든 JavaScript/TypeScript 구문을 완전하게 파싱하지 않습니다.
- native build, 복잡한 shell wrapper, 동적 import/require, runtime eval은 제한적으로만 처리됩니다.
- package-wide malware scanner가 아니라 lifecycle-hook review-scope triage 도구입니다.
- 출력 결과는 npm audit, GuardDog, Socket 같은 도구를 대체하지 않고 보완합니다.

## 안전 원칙

- 분석 대상 패키지를 설치하거나 실행하지 마세요.
- raw JSON에는 연구/디버깅용 세부 정보가 포함될 수 있으므로 외부 공유 전 검토하세요.
- token, secret, credential처럼 보이는 문자열은 human-readable 출력에서 redaction됩니다.
