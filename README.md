# npm-hook-risk

## 한국어 요약

`npm-hook-risk`는 npm `preinstall`, `install`, `postinstall` lifecycle hook을
실행하지 않고 정적으로 분석해, 보안 담당자가 먼저 검토할 파일, 라인, 행위 근거,
source-to-sink taint path를 좁혀 주는 review-priority triage 도구입니다.

이 저장소의 `public-release`는 제품형 악성 패키지 탐지기가 아니라
논문/졸업 연구에서 검증한 정적 트리아지 코어의 공개 preview입니다.
`High`는 악성 판정이 아니라 검토 우선순위이며, 미지원/실패 상태는 안전한
패키지로 낮춰 해석하지 않습니다.

주요 문서:

- [`docs/operational_guide_ko.md`](docs/operational_guide_ko.md): 한국어 실무 운영 가이드
- [`docs/architecture.md`](docs/architecture.md): 분석 파이프라인, trust boundary, Python 선택 이유
- [`docs/roadmap.md`](docs/roadmap.md): SARIF, policy, allowlist, parser worker, Rust/C 확장 로드맵
- [`examples/github-actions.yml`](examples/github-actions.yml): GitHub Actions 사용 예시

---

`npm-hook-risk` is a static review-priority triage tool for npm lifecycle
hooks. It does not execute package scripts and does not provide a
malicious/benign verdict.

This public release is a preview:

- Tool version: `0.1.0-preview`
- Engine profile: `public-preview-2026-06`
- Archived experiment reproduction claim: none
- Canonical-75 manifest and official experiment archive: not included in this product preview branch

The preview uses the analyzer source included in this release. It does not
claim byte-for-byte reproduction of the legacy archived rule identifier
recorded in earlier experimental artifacts.

For Korean users, see [`docs/operational_guide_ko.md`](docs/operational_guide_ko.md)
for a practical workflow, output interpretation notes, and CI usage guidance.

Architecture and productization notes:

- [`docs/architecture.md`](docs/architecture.md): pipeline, trust boundaries, and why Python is used.
- [`docs/roadmap.md`](docs/roadmap.md): SARIF, policy, parser backend, and Rust/C worker roadmap.
- [`examples/github-actions.yml`](examples/github-actions.yml): minimal CI usage example.

## Install

```bash
git clone <this-repository-url>
cd npm-hook-risk
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install -e .
```

## Quick Start

Use the tool as a first-pass review aid before installing or approving an npm
package with lifecycle hooks:

```bash
npm-hook-risk scan .
npm-hook-risk scan package@1.2.3
npm-hook-risk scan @scope/package@1.2.3
npm-hook-risk scan . --details
npm-hook-risk scan . --json
npm-hook-risk scan . --strict
```

Suggested workflow:

1. Run the default summary to see the review priority and lifecycle hooks.
2. Re-run with `--details` when the priority is Medium/High or analysis is partial.
3. Review the listed files, lines, behaviors, and taint paths manually.
4. Treat unsupported commands, parse failures, timeouts, and registry errors as
   unresolved review states, not as safe packages.

Python fallback:

```bash
python -m npm_hook_risk scan .
```

Example:

```bash
npm-hook-risk scan samples/taint_package
```

The default output is a human-readable summary. `High` means review priority,
not a malicious verdict. A Low or unavailable result is not package approval;
it only describes what this static preview could or could not analyze.

## CLI

```text
npm-hook-risk --help
npm-hook-risk scan --help
npm-hook-risk scan <package-directory|package@version>
```

Common options:

- `--details`: print category evidence, taint path summary, score contribution,
  files, lines, and limitations.
- `--json`: print stable user-facing JSON matching
  `schemas/user_summary.schema.json`.
- `--strict`: return a nonzero exit code for High review priority or failure
  status.
- `--output PATH`: write JSON output to a file.
- `--debug`: include traceback for CLI debugging.

Advanced/debug option:

- `--raw-json`: print the raw analyzer result for compatibility. Raw JSON is
  not redacted or simplified for normal user review.

Deprecated aliases:

- `--summary`: summary is now the default.
- `--explain`: use `--details`.

## Registry Package Scans

`package@version` scans fetch npm registry metadata, require an exact version,
verify `dist.integrity` or `dist.shasum`, safely extract the tarball, and then
run static analysis without executing lifecycle scripts.

Safety limits include tarball size, extracted byte count, member count, path
traversal blocking, symlink escape blocking, temporary directory cleanup, and
network timeout handling.

## Reading the Output

The CLI is designed to answer three practical questions:

- Which lifecycle hooks exist, and which local JavaScript files are reachable
  from those hooks?
- Which review-priority behaviors were observed, such as environment access,
  external communication, command execution, file modification, obfuscation, or
  CI/CD targeting?
- Which files and lines should a reviewer inspect first?

`--details` prints the most useful human review view: score reasons, behavior
labels, taint summaries, recommended review locations, and known limitations.
`--json` is intended for CI systems and wrappers that need a stable schema.
`--raw-json` is a debugging compatibility view and may contain unredacted raw
analyzer details.

## Review Priority Semantics

The preview engine includes the current public analyzer implementation,
including CI/CD targeting signals and related score contributions. This scoring
extension is part of the preview engine and requires separate validation.

Do not interpret output as:

- a malicious verdict
- package safety approval
- detection accuracy
- a production-ready malicious detector

Unsupported hooks, parse failures, timeouts, and analysis errors are not
converted into Low.

## JSON and CI

Use `--json` for stable user-facing JSON:

```bash
npm-hook-risk scan samples/taint_package --json --output summary.json
```

In CI, use `--strict` when you want Medium/Low completed analyses to pass but
High review priority, unsupported hook forms, and analysis failures to stop the
job. This is intentionally conservative: failure states are not silently
converted into Low.

Exit codes:

| Code | Meaning |
|---:|---|
| 0 | Analysis completed, no lifecycle hook, or non-strict unsupported/failure status |
| 1 | Input or usage error |
| 2 | Analysis failure in strict mode |
| 3 | Strict mode: High review priority |
| 4 | Strict mode: unsupported hook/language |
| 5 | Output file write failure |
| 6 | Registry metadata, download, integrity, or extraction failure |

## Research Provenance Note

Earlier archived artifacts record the legacy rule identifier
`sha256:df78653a5630ef4ac8b894f8122a9a621ec0e6d8906ccc8e9c2f4b72d46f254a`.

That identifier could not be recomputed from the Git objects currently
available in this repository. It is retained as historical metadata and is not
presented as the source hash of this preview release.

This release records a separate, reproducible public engine manifest derived
from the source files included in the release. The public manifest uses Git blob
object IDs and canonical JSON, so it is independent of Windows CRLF checkout
bytes.

Generate a release manifest from a clean checkout:

```bash
python -m npm_hook_risk manifest --output provenance/public_engine_manifest.json
```

Dirty checkouts are rejected for release manifest generation.

## Security Notice

- The tool performs static analysis and does not execute package scripts.
- Treat samples and third-party packages as untrusted.
- Do not install or run unknown packages solely because this tool reports Low
  or unavailable review priority.
- Human-readable output redacts token-like URL and credential material. Raw JSON
  is intended for advanced debug use.

