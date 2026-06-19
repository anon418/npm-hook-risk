"""Reproducible public-preview engine source provenance."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import ENGINE_PROFILE, LEGACY_RECORDED_RULE_HASH, TOOL_VERSION

PUBLIC_RULE_FILES = (
    "cli/presenter.py",
    "npm_hook_risk/cli.py",
    "npm_hook_risk/provenance.py",
    "npm_hook_risk/registry.py",
    "tools/analyze_package.py",
    "tools/ast_utils.py",
    "tools/taint_analyzer.py",
    "tools/taint_rules.py",
)


class DirtySourceError(RuntimeError):
    """Raised when a release manifest is requested from a dirty checkout."""


def canonical_json(payload: dict[str, Any]) -> str:
    """Serialize with stable JSON settings used for manifest hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def git_output(root: Path, args: list[str]) -> str:
    """Run a read-only Git command and return stdout."""
    completed = subprocess.run(
        ["git", *args],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def git_dirty(root: Path) -> tuple[bool, list[str]]:
    """Return dirty state and status lines."""
    lines = [line for line in git_output(root, ["status", "--short"]).splitlines() if line]
    return bool(lines), lines


def git_blob_sha(root: Path, relative_path: str, commit: str = "HEAD") -> str | None:
    """Return the Git blob object id for one tracked file, if committed."""
    try:
        return git_output(root, ["rev-parse", f"{commit}:{relative_path}"])
    except subprocess.CalledProcessError:
        return None


def working_tree_lf_sha256(root: Path, relative_path: str) -> str:
    """Hash working-tree bytes after normalizing CRLF to LF."""
    data = (root / relative_path).read_bytes().replace(b"\r\n", b"\n")
    return hashlib.sha256(data).hexdigest()


def build_public_engine_manifest(
    root: Path,
    *,
    require_clean: bool = False,
    generated_at: str | None = None,
    command: list[str] | None = None,
) -> dict[str, Any]:
    """Build a deterministic public engine manifest from tracked Git blobs."""
    root = root.resolve()
    dirty, dirty_files = git_dirty(root)
    if require_clean and dirty:
        raise DirtySourceError("public engine manifest release requires a clean Git tree")
    commit = git_output(root, ["rev-parse", "HEAD"])
    files = []
    for path in sorted(PUBLIC_RULE_FILES):
        files.append(
            {
                "path": path,
                "git_blob_sha": git_blob_sha(root, path, commit),
                "working_tree_lf_sha256": working_tree_lf_sha256(root, path),
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "tool_version": TOOL_VERSION,
        "engine_profile": ENGINE_PROFILE,
        "legacy_recorded_rule_hash": LEGACY_RECORDED_RULE_HASH,
        "legacy_hash_note": (
            "metadata-recorded identifier; not reproducible from currently "
            "reachable Git objects"
        ),
        "git_commit": commit,
        "git_dirty": dirty,
        "git_dirty_files": dirty_files,
        "rule_files": files,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "generated_by": command or ["python", "-m", "npm_hook_risk", "manifest"],
    }
    hash_payload = dict(payload)
    hash_payload.pop("generated_at", None)
    hash_payload.pop("generated_by", None)
    payload["public_engine_manifest_hash"] = (
        "sha256:" + hashlib.sha256(canonical_json(hash_payload).encode("utf-8")).hexdigest()
    )
    return payload


def write_manifest(root: Path, output: Path) -> dict[str, Any]:
    """Write a clean-release manifest to disk."""
    manifest = build_public_engine_manifest(root, require_clean=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(canonical_json(manifest) + "\n", encoding="utf-8")
    return manifest
