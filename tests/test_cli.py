import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import unittest
import uuid
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from npm_hook_risk.cli import run_scan
from npm_hook_risk.registry import RegistryError, _extract_tarball, parse_package_spec


ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / ".test-tmp"
SAMPLE_PACKAGE = str(Path("samples") / "taint_package")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "npm_hook_risk", *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def make_package(self, package_json: str, files: dict[str, str] | None = None) -> Path:
        path = TMP_ROOT / f"cli-{uuid.uuid4().hex}"
        path.mkdir(parents=True, exist_ok=False)
        (path / "package.json").write_text(package_json, encoding="utf-8")
        for name, content in (files or {}).items():
            file_path = path / name
            file_path.parent.mkdir(parents=True, exist_ok=True)
            file_path.write_text(content, encoding="utf-8")
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        return path

    def test_top_level_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("npm-hook-risk", result.stdout)
        self.assertIn("scan", result.stdout)

    def test_scan_help(self):
        result = self.run_cli("scan", "--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--details", result.stdout)
        self.assertIn("--json", result.stdout)
        self.assertNotIn("--raw-json", result.stdout)

    def test_valid_package_summary_shows_entry_file(self):
        result = self.run_cli("scan", SAMPLE_PACKAGE)
        self.assertEqual(result.returncode, 0)
        self.assertIn("Engine profile: public-preview-2026-06", result.stdout)
        self.assertIn("Review priority: High", result.stdout)
        self.assertIn("Malicious verdict: Not provided", result.stdout)
        self.assertIn("Main file: install.js", result.stdout)

    def test_json_output_is_user_summary(self):
        result = self.run_cli("scan", SAMPLE_PACKAGE, "--json")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["schema_version"], "1.0")
        self.assertEqual(payload["engine_profile"], "public-preview-2026-06")
        self.assertFalse(payload["review_priority"]["is_malicious_verdict"])
        self.assertEqual(payload["scope"]["entry_files"], ["install.js"])

    def test_details_alias_and_strict_high_exit_code(self):
        result = self.run_cli("scan", SAMPLE_PACKAGE, "--strict", "--details")
        self.assertEqual(result.returncode, 3)
        self.assertIn("Detailed evidence:", result.stdout)
        self.assertIn("High means review priority", result.stdout)

    def test_missing_package_json_has_no_traceback(self):
        path = TMP_ROOT / f"empty-{uuid.uuid4().hex}"
        path.mkdir(parents=True)
        self.addCleanup(lambda: shutil.rmtree(path, ignore_errors=True))
        result = self.run_cli("scan", str(path))
        self.assertEqual(result.returncode, 1)
        self.assertIn("package.json was not found", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_unsupported_shell_hook_status(self):
        path = self.make_package('{"name":"native","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}')
        result = self.run_cli("scan", str(path), "--strict")
        self.assertEqual(result.returncode, 4)
        self.assertIn("Unsupported lifecycle command form", result.stdout)

    def test_raw_json_keeps_analyzer_shape(self):
        result = self.run_cli("scan", SAMPLE_PACKAGE, "--raw-json")
        self.assertEqual(result.returncode, 0)
        payload = json.loads(result.stdout)
        self.assertIn("hooks", payload)
        self.assertIn("taint_paths", payload)

    def test_package_spec_parser(self):
        self.assertEqual(parse_package_spec("lodash@4.17.21").name, "lodash")
        self.assertEqual(parse_package_spec("@scope/pkg@1.2.3").name, "@scope/pkg")
        self.assertIsNone(parse_package_spec("lodash"))


class RegistryExtractionTests(unittest.TestCase):
    def make_tarball(self, package_json: dict, files: dict[str, str] | None = None) -> bytes:
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            payloads = {"package/package.json": json.dumps(package_json)}
            payloads.update(files or {})
            for name, content in payloads.items():
                data = content.encode("utf-8")
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return stream.getvalue()

    def test_extract_blocks_path_traversal(self):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            data = b"bad"
            info = tarfile.TarInfo("../evil.js")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        with self.assertRaises(RegistryError):
            _extract_tarball(stream.getvalue(), TMP_ROOT / f"extract-{uuid.uuid4().hex}")

    def test_registry_scan_uses_mocked_tarball(self):
        tarball = self.make_tarball(
            {"name": "demo", "version": "1.0.0", "scripts": {"postinstall": "node install.js"}},
            {"package/install.js": "console.log(process.env.NPM_TOKEN);"},
        )
        integrity = "sha512-" + base64.b64encode(hashlib.sha512(tarball).digest()).decode("ascii")
        metadata = {
            "versions": {
                "1.0.0": {
                    "dist": {
                        "tarball": "https://registry.example/demo.tgz",
                        "integrity": integrity,
                    }
                }
            }
        }

        class Response:
            def __init__(self, data):
                self.data = io.BytesIO(data)
            def __enter__(self):
                return self
            def __exit__(self, *exc):
                return False
            def read(self, size=-1):
                return self.data.read(size)

        def fake_urlopen(request, timeout=0):
            url = getattr(request, "full_url", str(request))
            if url.endswith("demo"):
                return Response(json.dumps(metadata).encode("utf-8"))
            return Response(tarball)

        with patch("npm_hook_risk.registry.urlopen", fake_urlopen):
            code = run_scan(
                Namespace(
                    target="demo@1.0.0",
                    summary=False,
                    explain=False,
                    details=False,
                    json=True,
                    raw_json=False,
                    output=None,
                    strict=False,
                )
            )
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()

