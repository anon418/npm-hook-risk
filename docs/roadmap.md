# Roadmap

This roadmap separates the current public preview from future engineering and
evaluation work. The v0.1 preview is intentionally conservative: it exposes
review-priority evidence and failure states without claiming production-ready
malware detection.

## v0.1.0-preview: public preview

Status: current public-release target.

Included:

- static npm lifecycle-hook triage,
- exact `package@version` registry fetch,
- integrity verification and safe extraction,
- user-facing summary, details, and JSON output,
- failure-aware terminal states,
- Korean operational guide,
- source comments explaining core review boundaries.

Not claimed:

- malicious/benign verdicts,
- detection accuracy,
- production-ready policy enforcement,
- large-scale npm ecosystem coverage,
- reproduction of the archived canonical-75 experiment bundle from this branch.

## v0.2: operational CLI hardening

Planned additions:

- SARIF output for GitHub code scanning and security dashboards,
- `policy.yml` for organization-specific fail conditions,
- allowlist/ignore files for reviewed packages or known benign hooks,
- GitHub Actions examples and release checklist,
- packaged preview releases.

The key rule for this stage is that policy configuration must not silently
change the underlying analyzer evidence. It should only change how an
organization reacts to the evidence.

## v0.3: parser backend separation

Planned additions:

- locked Node/Acorn or Babel parser worker,
- structured file-level parser provenance,
- bounded timeout and terminate/kill cleanup,
- better modern JavaScript and ESM coverage,
- malformed-source diagnostics.

Parser coverage improvements should be reported as structural coverage, not as
malicious detection performance.

## v0.4: high-throughput and sandboxing track

Candidate Rust/C/Go components:

- archive validation and extraction,
- sandboxed parser supervisor,
- high-volume registry scan scheduler,
- resource accounting,
- single-binary or hybrid distribution.

This stage is appropriate after the review-priority model and corpus protocol
are stable enough to justify production-scale engineering.

## Evaluation v2: reviewer-facing research hardening

These items are evaluation work, not product claims. They are the highest-value
next steps before a journal-scale submission.

### Short-cycle analyses

- Parser coverage report on canonical-75: count `success`, `partial_success`,
  `parse_failure`, `unsupported_language`, `timeout`, and other failure states;
  explain why the non-analyzable samples are not included in score-based tables.
- Benign high-priority review: list benign/control samples that receive High
  review priority and explain the evidence category, without calling them false
  positives unless a separate decision threshold is defined.
- Threat model section: state which lifecycle-hook attacker behaviors are in
  scope and which behaviors are out of scope, such as runtime-downloaded
  payloads, WASM/Bun-only payloads, dynamic `eval`, and non-JavaScript installers.
- Temporal split audit: reuse package publication dates to report how the
  canonical corpus behaves under a time-aware split.

### Medium-cycle analyses

- Weight sensitivity: perturb category and combo weights, for example within a
  fixed +/-50% range, and report whether structural participation counts and
  review bands are stable. This must not be presented as threshold tuning.
- Keyword-only or manifest-only baseline: compare review surface and evidence
  quality under a shared lifecycle-hook scope, without claiming precision,
  recall, or detection-rate superiority.

### Long-cycle validation

- External reviewer utility study: ask security practitioners whether the
  output helps choose files and lines to inspect. This may require a study
  protocol and ethics review.
- ATCA follow-up: treat AI-agent configuration analysis as a separate study
  unless the repository includes its implementation, corpus, fixtures, and
  empirical validation.

## Evaluation follow-up

Before claiming a stronger decision layer, the project needs:

- larger family-aware malicious and benign corpora,
- version-level provenance for malicious samples,
- held-out evaluation splits,
- threshold and policy evaluation,
- comparison with existing tools under a shared scope.
