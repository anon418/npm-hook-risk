import unittest
from pathlib import Path
from unittest.mock import patch

from npm_hook_risk.provenance import (
    DirtySourceError,
    build_public_engine_manifest,
    canonical_json,
)


ROOT = Path(__file__).resolve().parents[1]


class PublicProvenanceTests(unittest.TestCase):
    def test_manifest_has_public_and_legacy_fields(self):
        manifest = build_public_engine_manifest(ROOT)
        self.assertEqual(manifest["engine_profile"], "public-preview-2026-06")
        self.assertIn("legacy_recorded_rule_hash", manifest)
        self.assertIn("public_engine_manifest_hash", manifest)
        self.assertIn("not reproducible", manifest["legacy_hash_note"])

    def test_manifest_json_is_deterministic_without_timestamp(self):
        first = build_public_engine_manifest(ROOT, generated_at="2026-01-01T00:00:00+00:00", command=["x"])
        second = build_public_engine_manifest(ROOT, generated_at="2026-02-01T00:00:00+00:00", command=["y"])
        self.assertEqual(first["public_engine_manifest_hash"], second["public_engine_manifest_hash"])
        self.assertEqual(canonical_json({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_dirty_release_is_rejected(self):
        with patch("npm_hook_risk.provenance.git_dirty", return_value=(True, [" M README.md"])):
            with self.assertRaises(DirtySourceError):
                build_public_engine_manifest(ROOT, require_clean=True)


if __name__ == "__main__":
    unittest.main()
