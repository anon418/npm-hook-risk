# Reproducibility Notes

This public branch is a product-oriented preview. It keeps the runnable CLI,
minimal samples, tests, schema, and source provenance helper while excluding the
internal experiment archive.

The canonical-75 manifest and full official experiment artifacts are managed as a separate supplementary archive, not as part of this product preview branch.

## Public Engine Manifest

A clean checkout can generate a deterministic manifest for the public preview
source files:

```bash
python -m npm_hook_risk manifest --output provenance/public_engine_manifest.json
```

The manifest records:

- tool version and engine profile;
- current Git commit and dirty state;
- public engine source file list;
- Git blob ids and LF-normalized working-tree SHA-256 values;
- a deterministic public engine manifest hash.

Dirty checkouts are rejected when writing a release manifest.

## Runtime Verification

Recommended local checks:

```bash
python -B -m unittest discover -s tests -v
python -B -m npm_hook_risk scan samples/taint_package --details
```

Network-backed registry tests are intentionally not part of the minimal product
preview test set. Registry download behavior is covered with mocked tarball and
integrity fixtures in `tests/test_cli.py`.

## Legacy Archived Hash

Earlier archived artifacts recorded a legacy rule identifier. The public preview
keeps that value as historical metadata only and does not claim byte-for-byte
reproduction of the archived run.

