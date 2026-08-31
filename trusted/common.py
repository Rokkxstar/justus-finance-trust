"""Immutable identities and independent evidence parsing for the Phase-5 exit."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Sequence


CANDIDATE_REPOSITORY = "Rokkxstar/JUSTUS"
CANDIDATE_COMMIT = "123c29f149cb25a4f270979708bdccf266c130e8"
CANDIDATE_SNAPSHOT = "83f99826170ba24e84438669cfd3754094c581ac080476e314a8638172823db7"
PRODUCT_OWNER_LEDGER_SHA256 = "84bd9d65e499c858e4e3c947805c3df9eb19c37bd55e06ebb0031e0f7e3bfb21"
PARENT_PHASE4_SHA256 = "005e4f04ac66bde18faab9a367e1a287a9b71ad984934e5f9e6b91eff6ebca32"
PRE_RETROFIT_PHASE5_SHA256 = "71d29269dddd8694e1ab191328047a4f29fcf978b60231440a0c06b6ef702236"
ARCHIVE_ROOT = "phase-5-release"

ACCEPTED_BASELINES = {
    "0": "77b709e9d08c2efb5042f9cfaaa6229b53839898e7394866f1ab9e84d4aa093f",
    "1": "39a30ebd24fe506eac92babd72876290a2b7f8bbc64fba9a0826070ac910f256",
    "2": "d8b3fb56a74b4756548199a7e747a41f8714df9403e64303cc20b4cb64c90bc4",
    "3": "efc75ba7327f5836d4fc9ca4a0c7ee27d479b8e94ab6ea82d7614eb19a5afa56",
    "4": PARENT_PHASE4_SHA256,
}

# The accepted local candidate predates Git transport and contains CRLF only in
# these eight JSON fixtures. Git stores text canonically as LF, so an exact
# checkout cannot reproduce the already accepted byte snapshot on its own.
# The external trust root restores only these independently hash-pinned bytes
# and then requires the complete candidate snapshot to match.
CRLF_TRANSPORT_RECONSTRUCTION = {
    "golden_cases/phase4-repository-attestations.json": "6a620a90ca189bcd7fbca6a1f9fda741b146e89f53123ae3290b2606c8403f25",
    "golden_cases/phase4/p4-cf-01.json": "2532e7212bce743908d8aecb9a33984972c33e3fa66f0858958c6dd8214f5349",
    "golden_cases/phase4/p4-cf-02.json": "7cb1930775b6f127f6a84f09017532643a4a07035723fdb374d3c8c5d23d6565",
    "golden_cases/phase4/p4-cf-03.json": "dda2d38d2fca7045cf5f740bb95a33f1d9c458219b9835077ecf75f40570e015",
    "golden_cases/phase4/p4-cf-04.json": "70bc917023f90f60d9eb94f64d49d7aec4dd9660f7d91ee16afa42c4789ea92c",
    "golden_cases/phase4/p4-cf-05.json": "9c670b1367425e0ebb7c5ad5cd733bc1fd1c1fcc02b1e8c801ff834a2958361c",
    "golden_cases/phase4/p4-cf-06.json": "b299fee47ebf8a2cd085d40b9a97dae38149243e5c0b80d2ebd544d59fa5aeac",
    "golden_cases/phase4/p4-cf-07.json": "715751618ccbe966cd6d700d9ccdd74a968fca594dd0826d2e3d5a6a068d8d1d",
}

UNITTEST_CASE = re.compile(r"^test_[^ ]+ \(([^)]+)\) \.\.\. ok$")
UNITTEST_COUNT = re.compile(r"^Ran ([0-9]+) tests? in .+$")
RELEASE_IDENTITY = re.compile(r"^phase-5-exit-[0-9]{8}T[0-9]{6}Z-([0-9a-f]{12})$")
HASH = re.compile(r"^[0-9a-f]{64}$")


class TrustError(RuntimeError):
    """A fail-closed violation at the independent trust boundary."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise TrustError(f"{label} fields differ from the trusted schema")
    return value


def require_release_identity(value: str) -> None:
    match = RELEASE_IDENTITY.fullmatch(value)
    if match is None or match.group(1) != CANDIDATE_SNAPSHOT[:12]:
        raise TrustError(
            "release identity must be canonical and end in the independently verified candidate snapshot prefix "
            f"{CANDIDATE_SNAPSHOT[:12]}"
        )


def _selected_files(root: Path, folders: Iterable[tuple[str, tuple[str, ...]]], singles: Iterable[str] = ()) -> tuple[Path, ...]:
    result = [root / item for item in singles if (root / item).is_file()]
    for folder, suffixes in folders:
        base = root / folder
        if base.is_dir():
            result.extend(
                path for path in base.rglob("*")
                if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts
            )
    return tuple(sorted(set(result), key=lambda path: path.relative_to(root).as_posix()))


def source_material_files(root: Path) -> tuple[Path, ...]:
    return _selected_files(
        root,
        (
            ("docs", (".md",)), ("src", (".py",)), ("tests", (".py",)),
            ("golden_cases", (".json",)), ("scripts", (".py",)), ("supabase", (".sql",)),
            ("outputs/phase-0", (".md", ".txt")), ("outputs/phase-1", (".md", ".txt")),
            ("outputs/phase-2", (".md", ".txt")), ("outputs/phase-3", (".md", ".txt")),
            ("outputs/phase-4", (".md", ".txt")), ("outputs/phase-5", (".md", ".txt")),
        ),
        (".gitignore", "README.md", "pyproject.toml", "requirements.txt", "requirements-dev.txt", "requirements.lock"),
    )


def governance_control_files(root: Path) -> tuple[Path, ...]:
    files = list(_selected_files(root, ((".github", (".yml", ".yaml")), ("governance", (".md", ".json")))))
    return tuple(
        path for path in files
        if "evidence" not in path.relative_to(root).parts
        and "impact-declarations" not in path.relative_to(root).parts
        and "acceptance-contracts" not in path.relative_to(root).parts
        and "metrics" not in path.relative_to(root).parts
    )


def _tree_digest(paths: Iterable[Path], root: Path) -> str:
    manifest = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path), "size": path.stat().st_size}
        for path in paths
    ]
    return sha256_bytes(canonical_json(manifest))


def candidate_snapshot(root: Path) -> dict[str, str]:
    core = {
        "algorithm": "sha256-canonical-file-manifest-v1",
        "sourceMaterialSha256": _tree_digest(source_material_files(root), root),
        "governanceControlsSha256": _tree_digest(governance_control_files(root), root),
        "parentAcceptedBaselineSha256": PARENT_PHASE4_SHA256,
    }
    snapshot = {**core, "combinedSha256": sha256_bytes(canonical_json(core))}
    if snapshot["combinedSha256"] != CANDIDATE_SNAPSHOT:
        raise TrustError(f"candidate source snapshot mismatch: {snapshot['combinedSha256']}")
    return snapshot


def restore_git_transport_bytes(root: Path) -> None:
    """Reconstruct the accepted mixed-newline bytes from an LF-only checkout."""

    for relative, expected_hash in CRLF_TRANSPORT_RECONSTRUCTION.items():
        path = root / relative
        if not path.is_file():
            raise TrustError(f"transport reconstruction input is missing: {relative}")
        content = path.read_bytes()
        if sha256_bytes(content) == expected_hash:
            continue
        if b"\r\n" in content or b"\r" in content:
            raise TrustError(f"transport reconstruction input has unexpected newlines: {relative}")
        reconstructed = content.replace(b"\n", b"\r\n")
        if sha256_bytes(reconstructed) != expected_hash:
            raise TrustError(f"transport reconstruction hash mismatch: {relative}")
        path.write_bytes(reconstructed)


def validate_candidate_identity(root: Path) -> dict[str, str]:
    ledger = root / "governance" / "product-owner-trust-ledger.json"
    if not ledger.is_file() or sha256_file(ledger) != PRODUCT_OWNER_LEDGER_SHA256:
        raise TrustError("candidate Product-Owner ledger does not match the independent trust anchor")
    external = os.environ.get("FINANCE_PO_TRUST_LEDGER_SHA256", "").lower()
    if external != PRODUCT_OWNER_LEDGER_SHA256:
        raise TrustError("protected environment Product-Owner ledger SHA-256 is missing or wrong")
    for phase, expected in ACCEPTED_BASELINES.items():
        archive = root / "outputs" / f"phase-{phase}.zip"
        if not archive.is_file() or sha256_file(archive) != expected:
            raise TrustError(f"accepted phase-{phase} baseline differs from the independent trust registry")
    return candidate_snapshot(root)


def declared_test_ids(path: Path, module: str) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    return sorted(
        f"{module}.{node.name}.{member.name}"
        for node in tree.body if isinstance(node, ast.ClassDef)
        for member in node.body
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_")
    )


def parse_case_results(kind: str, contract_path: str, output: str, expected: Sequence[str] | None = None) -> list[dict[str, str]]:
    lines = [line.strip() for line in output.splitlines()]
    if kind == "UNITTEST":
        observed = [match.group(1) for line in lines if (match := UNITTEST_CASE.fullmatch(line))]
        counts = [int(match.group(1)) for line in lines if (match := UNITTEST_COUNT.fullmatch(line))]
        if len(counts) != 1 or counts[0] != len(observed) or "OK" not in lines:
            raise TrustError(f"{contract_path}: incoherent unittest evidence")
        if expected is not None and sorted(observed) != sorted(expected):
            raise TrustError(f"{contract_path}: executed unittest IDs differ from reviewed source")
        case_ids = observed
    elif kind in {"POSTGRESQL", "GOLDEN"} or contract_path.endswith(("golden_cases.py", "postgres_tests.py")):
        case_ids = [line[5:].split()[0] for line in lines if line.startswith("PASS ") and len(line.split()) >= 2]
        if not case_ids or not any("passed" in line.lower() and "/" in line for line in lines):
            raise TrustError(f"{contract_path}: missing individual PASS cases or coherent summary")
    else:
        if not any(len(line) >= 12 and "PASS" in line for line in lines):
            raise TrustError(f"{contract_path}: missing meaningful PASS statement")
        case_ids = [f"SCRIPT:{contract_path}"]
    if not case_ids or len(case_ids) != len(set(case_ids)):
        raise TrustError(f"{contract_path}: case IDs are empty or duplicated")
    return [{"caseId": item, "status": "PASS"} for item in case_ids]


def run_checked(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    log_path: Path,
    label: str,
) -> str:
    result = subprocess.run(
        list(command), cwd=cwd, env=environment, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_path.write_text(result.stdout, encoding="utf-8")
    if result.returncode != 0:
        raise TrustError(f"{label} failed with exit code {result.returncode}; log={log_path}")
    return result.stdout


def candidate_environment(root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    # Candidate processes must never inherit workflow command files, OIDC or
    # artifact-service credentials. In particular, hiding GITHUB_OUTPUT keeps
    # the immutable job outputs outside candidate control.
    for key in tuple(environment):
        if key.startswith(("GITHUB_", "ACTIONS_")) or key in {
            "JUSTUS_READ_TOKEN", "FINANCE_PO_TRUST_LEDGER_SHA256",
        }:
            environment.pop(key, None)
    environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root)))
    if not environment.get("PHASE2_POSTGRES_BIN"):
        raise TrustError("trusted PostgreSQL runtime binding is missing")
    return environment


def safe_archive_manifest(path: Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise TrustError("release archive contains duplicate paths")
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or not pure.parts or pure.parts[0] != ARCHIVE_ROOT:
                raise TrustError(f"unsafe release archive path: {name}")
        manifest_name = f"{ARCHIVE_ROOT}/release-manifest.json"
        if names.count(manifest_name) != 1:
            raise TrustError("release archive must contain exactly one manifest")
        manifest = json.loads(archive.read(manifest_name))
        files = manifest.get("files")
        if not isinstance(files, list):
            raise TrustError("release manifest files are missing")
        expected_names = {manifest_name}
        for entry in files:
            require_fields(entry, {"path", "sha256", "size"}, "release manifest entry")
            name = f"{ARCHIVE_ROOT}/{entry['path']}"
            content = archive.read(name)
            if len(content) != entry["size"] or sha256_bytes(content) != entry["sha256"]:
                raise TrustError(f"release manifest mismatch: {entry['path']}")
            expected_names.add(name)
        if set(names) != expected_names:
            raise TrustError("release archive inventory differs from manifest")
    return manifest


def python_command(*parts: str) -> list[str]:
    return [sys.executable, *parts]
