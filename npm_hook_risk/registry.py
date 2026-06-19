"""공개 CLI를 위한 npm registry 패키지 다운로드와 안전한 압축 해제.

install script는 절대 실행하지 않고, exact version만 받으며, registry integrity를 검증한다.
크기/멤버 수 제한과 path traversal 차단은 공급망 분석 도구의 기본 안전 경계다.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import re
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

MAX_TARBALL_BYTES = 50 * 1024 * 1024
MAX_EXTRACTED_BYTES = 50 * 1024 * 1024
MAX_TAR_MEMBERS = 10000
NETWORK_TIMEOUT_SECONDS = 30

PACKAGE_SPEC_RE = re.compile(
    r"^(?P<name>(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+)@(?P<version>[0-9][^@]*)$"
)


class RegistryError(RuntimeError):
    """Public-facing registry or archive processing error."""


@dataclass(frozen=True)
class PackageSpec:
    name: str
    version: str


def parse_package_spec(spec: str) -> PackageSpec | None:
    """Parse exact npm package specs like ``name@1.0.0`` and scoped specs."""
    match = PACKAGE_SPEC_RE.fullmatch(spec)
    if not match:
        return None
    return PackageSpec(match.group("name"), match.group("version"))


def fetch_package_to_temp(spec: PackageSpec) -> tempfile.TemporaryDirectory[str]:
    """패키지를 다운로드, 검증, 안전 해제하여 임시 디렉터리에 둔다.

    반환된 TemporaryDirectory가 압축 해제된 패키지의 생명주기를 가진다. 호출자는
    context manager로 사용해 정적 분석 후 신뢰하지 않는 파일을 정리해야 한다.
    """
    temporary = tempfile.TemporaryDirectory(prefix="npm-hook-risk-")
    try:
        root = Path(temporary.name)
        metadata = _fetch_metadata(spec.name)
        version_info = (metadata.get("versions") or {}).get(spec.version)
        if not isinstance(version_info, dict):
            raise RegistryError(f"exact version not found: {spec.name}@{spec.version}")
        dist = version_info.get("dist") or {}
        tarball = dist.get("tarball")
        if not isinstance(tarball, str):
            raise RegistryError("registry metadata does not include dist.tarball")
        data = _download(tarball, MAX_TARBALL_BYTES)
        _verify_dist(data, dist)
        package_root = _extract_tarball(data, root)
        package_json = json.loads((package_root / "package.json").read_text(encoding="utf-8"))
        if package_json.get("name") != spec.name or package_json.get("version") != spec.version:
            raise RegistryError("package.json name/version does not match requested spec")
        return temporary
    except Exception:
        temporary.cleanup()
        raise


def _fetch_metadata(name: str) -> dict[str, Any]:
    encoded = quote(name, safe="@")
    url = f"https://registry.npmjs.org/{encoded}"
    try:
        data = _download(url, MAX_TARBALL_BYTES)
    except URLError as exc:
        raise RegistryError(f"npm registry metadata request failed: {exc}") from exc
    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError("npm registry returned invalid JSON metadata") from exc


def _download(url: str, max_bytes: int) -> bytes:
    request = Request(url, headers={"User-Agent": "npm-hook-risk/0.1.0-preview"})
    try:
        with urlopen(request, timeout=NETWORK_TIMEOUT_SECONDS) as response:
            chunks: list[bytes] = []
            total = 0
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise RegistryError("download exceeded configured size limit")
                chunks.append(chunk)
            return b"".join(chunks)
    except TimeoutError as exc:
        raise RegistryError("network request timed out") from exc
    except URLError as exc:
        raise RegistryError(f"network request failed: {exc}") from exc


def _verify_dist(data: bytes, dist: dict[str, Any]) -> None:
    # npm이 제공하는 Subresource Integrity를 우선 검증하고, 없을 때만 legacy shasum을 쓴다.
    integrity = dist.get("integrity")
    shasum = dist.get("shasum")
    if isinstance(integrity, str):
        algorithm, encoded = _parse_integrity(integrity)
        expected = base64.b64decode(encoded, validate=True)
        calculated = hashlib.new(algorithm, data).digest()
        if not hmac.compare_digest(expected, calculated):
            raise RegistryError("npm integrity verification failed")
        return
    if isinstance(shasum, str):
        if not hmac.compare_digest(hashlib.sha1(data).hexdigest(), shasum):
            raise RegistryError("npm shasum verification failed")
        return
    raise RegistryError("registry metadata does not include integrity or shasum")


def _parse_integrity(value: str) -> tuple[str, str]:
    match = re.fullmatch(r"(sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})", value)
    if not match:
        raise RegistryError("unsupported npm integrity value")
    return match.group(1), match.group(2)


def _extract_tarball(data: bytes, destination: Path) -> Path:
    # 압축 해제 전에 모든 member를 검증한다. traversal/리소스 초과 실패를 예측 가능하게 남긴다.
    extracted_bytes = 0
    member_count = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive.getmembers():
            member_count += 1
            if member_count > MAX_TAR_MEMBERS:
                raise RegistryError("tarball exceeded configured member limit")
            if member.issym() or member.islnk():
                _validate_link(member)
                continue
            if not member.isfile() and not member.isdir():
                continue
            _safe_member_path(destination, member.name)
            if member.isfile():
                extracted_bytes += int(member.size)
                if extracted_bytes > MAX_EXTRACTED_BYTES:
                    raise RegistryError("tarball exceeded configured extracted size limit")
        archive.extractall(destination)
    package_root = destination / "package"
    if not (package_root / "package.json").is_file():
        raise RegistryError("extracted tarball does not contain package/package.json")
    return package_root


def _safe_member_path(root: Path, member_name: str) -> Path:
    path = (root / member_name).resolve()
    root_resolved = root.resolve()
    if path != root_resolved and root_resolved not in path.parents:
        raise RegistryError("tarball path traversal blocked")
    return path


def _validate_link(member: tarfile.TarInfo) -> None:
    link = Path(member.linkname)
    if link.is_absolute() or ".." in link.parts:
        raise RegistryError("tarball symlink escape blocked")
