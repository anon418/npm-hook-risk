# Public Release Checklist

Use this checklist before publishing a preview branch or tag.

## Identity and repository hygiene

- Confirm `git log --format="%h %an <%ae> %cn <%ce> | %s"` contains only the
  intended public identity.
- Search tracked files for personal names, emails, local paths, and institution
  identifiers.
- Keep dirty, exploratory, or archive-only artifacts out of the public release
  unless they are intentionally documented.

## Verification

```bash
python -B -m unittest discover -s tests -v
python -B -m npm_hook_risk scan samples/taint_package --details
python -B -m npm_hook_risk manifest --output provenance/public_engine_manifest.json
```

## Public messaging

- `High` is review priority, not a malicious verdict.
- Unsupported or failed analyses are unresolved review states.
- The preview is static and does not execute package scripts.
- The Python implementation is a readable preview core, not the final
  high-throughput scanner architecture.

