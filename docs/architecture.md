# Architecture Notes

`npm-hook-risk` is intentionally built as a static review-priority triage tool,
not as an automatic malicious-package detector.

## Design goal

The tool answers a narrow operational question:

> When an npm package has `preinstall`, `install`, or `postinstall` hooks, which
> local JavaScript files, behaviors, lines, and source-to-sink paths should a
> human reviewer inspect first?

It does not execute package scripts, does not install dependencies, and does not
produce a malicious/benign verdict.

## Main pipeline

1. Read `package.json`.
2. Identify npm lifecycle hooks in scope.
3. Resolve local JavaScript hook entry files when supported.
4. Parse JavaScript with bounded parser behavior.
5. Collect behavior categories using static rules.
6. Track selected source-to-sink taint paths.
7. Convert evidence into review-priority output.
8. Preserve unsupported, failed, or incomplete states instead of lowering them
   to Low.

## Why Python?

Python was selected for the public preview because the
project is currently evidence-oriented rather than throughput-oriented.

The main reasons are:

- Fast iteration on static-analysis rules and provenance fields.
- Simple JSON, CSV, tarball, and npm metadata processing.
- Easy inspection by security reviewers and maintainers.
- Lower implementation friction for provenance helpers and tests.
- Good fit for I/O-bound package triage where script execution is avoided.

C, Rust, or Go would be reasonable choices for later high-throughput components,
but they would not by themselves solve the design questions around scope,
failure provenance, review-priority evidence, and corpus limitations.

## Why not Rust/C first?

A lower-level implementation would be useful for:

- sandboxed parser workers,
- high-volume registry scanning,
- hardened archive extraction,
- bounded process supervision,
- static binary distribution.

Those are productization concerns. The current preview keeps the analyzer
readable and auditable so the preview behavior can be reviewed directly.
A future version can move selected hot or risky components behind process
boundaries without changing the review-priority semantics.

## Trust boundaries

- Registry fetch and tar extraction never execute package code.
- Unsupported lifecycle command forms remain explicit review states.
- Parser failure is treated as a coverage limitation, not as evidence of safety.
- `High` means review priority, not malicious prediction.
- Raw analyzer output is separated from stable user-facing JSON.

## Current limitations

- JavaScript parser compatibility is limited compared with a full modern parser
  backend.
- Shell, native build, and arbitrary interpreter hooks are not deeply analyzed.
- Rule weights are preview heuristics, not validated decision thresholds.
- Large-scale npm ecosystem scanning is outside the v0.1 preview scope.
