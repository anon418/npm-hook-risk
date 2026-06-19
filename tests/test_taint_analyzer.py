"""Tests for AST utilities and semantic taint analysis."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from analyze_package import analyze_package_dir
from ast_utils import MAX_JS_BYTES, get_call_name, parse_js, walk
from taint_analyzer import analyze_source


class AstUtilsTests(unittest.TestCase):
    """Verify bounded parsing and AST name extraction."""

    def test_parse_walk_and_call_name(self) -> None:
        ast = parse_js("const x = require('fs').readFileSync('/etc/hosts');")
        self.assertIsNotNone(ast)
        call = ast.body[0].declarations[0].init
        self.assertEqual(get_call_name(call), "fs.readFileSync")
        nodes: list[str] = []
        walk(ast, lambda node, parents: nodes.append(node.type))
        self.assertIn("CallExpression", nodes)

    def test_parse_failure_returns_none(self) -> None:
        self.assertIsNone(parse_js("const = ;"))

    def test_source_over_five_megabytes_is_rejected(self) -> None:
        self.assertIsNone(parse_js("a" * (MAX_JS_BYTES + 1)))


class TaintAnalyzerTests(unittest.TestCase):
    """Verify positive, negative, and representative malicious flows."""

    def test_amplitude_style_example_has_four_paths(self) -> None:
        source_path = ROOT / "samples" / "taint_package" / "install.js"
        paths = analyze_source(
            source_path.read_text(encoding="utf-8"),
            "install.js",
        )

        self.assertEqual(len(paths), 4)
        expressions = {path.source["expression"] for path in paths}
        self.assertTrue(any("execSync" in expression for expression in expressions))
        self.assertTrue(any("readFileSync" in expression for expression in expressions))
        self.assertIn("process.env.USER", expressions)
        self.assertTrue(any("os.userInfo" in expression for expression in expressions))
        self.assertTrue(all(path.sink["call"] == "req.write" for path in paths))
        self.assertTrue(any("webhook_url" in path.sink for path in paths))

    def test_synthetic_positive_samples(self) -> None:
        directory = ROOT / "samples" / "taint_positive"
        for path in directory.glob("*.js"):
            with self.subTest(sample=path.name):
                results = analyze_source(
                    path.read_text(encoding="utf-8"),
                    path.name,
                )
                self.assertGreaterEqual(len(results), 1)

    def test_synthetic_negative_samples(self) -> None:
        directory = ROOT / "samples" / "taint_negative"
        for path in directory.glob("*.js"):
            with self.subTest(sample=path.name):
                results = analyze_source(
                    path.read_text(encoding="utf-8"),
                    path.name,
                )
                self.assertEqual(results, [])

    def test_package_output_and_taint_scoring(self) -> None:
        result = analyze_package_dir(ROOT / "samples" / "taint_package")

        self.assertEqual(result["taint_path_count"], 4)
        self.assertEqual(len(result["taint_paths"]), 4)
        hook = result["hooks"]["postinstall"]
        self.assertEqual(hook["taint_path_count"], 4)
        self.assertGreaterEqual(hook["score"], 240)
        self.assertEqual(result["final_risk_level"], "High")

    def test_benign_package_snippets_have_no_paths(self) -> None:
        snippets = {
            "dotenv": "const path = require('path'); module.exports = path.resolve('.env');",
            "cross-env": "const env = Object.assign({}, process.env); console.log(env.PATH);",
            "chalk": "const enabled = process.env.FORCE_COLOR; module.exports = enabled;",
        }
        for package, source in snippets.items():
            with self.subTest(package=package):
                self.assertEqual(analyze_source(source, f"{package}.js"), [])


if __name__ == "__main__":
    unittest.main()
