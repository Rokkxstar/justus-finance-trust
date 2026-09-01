"""Execute immutable accepted-baseline contracts without candidate governance code."""

from __future__ import annotations

import ast
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from trusted.common import (
    ACCEPTED_BASELINES,
    TrustError,
    candidate_environment,
    candidate_snapshot,
    parse_case_results,
    python_command,
    run_checked,
    sha256_file,
    write_json,
)


def contract_kind(name: str) -> str:
    filename = PurePosixPath(name).name
    if "/tests/test_" in name:
        return "UNITTEST"
    if filename == "check_architecture.py":
        return "ARCHITECTURE"
    if filename.endswith("postgres_tests.py"):
        return "POSTGRESQL"
    if filename.endswith("golden_cases.py"):
        return "GOLDEN"
    if "/golden_cases/" in name:
        return "FIXTURE"
    return "OTHER"


def _safe_members(archive: zipfile.ZipFile) -> tuple[str, ...]:
    names = tuple(archive.namelist())
    if not names or len(names) != len(set(names)):
        raise TrustError("accepted archive is empty or contains duplicate paths")
    roots: set[str] = set()
    for info in archive.infolist():
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            raise TrustError(f"unsafe accepted archive path: {info.filename}")
        if ((info.external_attr >> 16) & 0o170000) == 0o120000:
            raise TrustError(f"accepted archive contains a symbolic link: {info.filename}")
        roots.add(path.parts[0])
    if len(roots) != 1:
        raise TrustError("accepted archive must contain exactly one root")
    return names


def _verify_manifest(archive: zipfile.ZipFile, names: tuple[str, ...], root_name: str) -> tuple[int, dict[str, str]]:
    manifest_name = f"{root_name}/release-manifest.json"
    if manifest_name not in names:
        files = [name for name in names if not name.endswith("/")]
        return len(names), {name: hashlib.sha256(archive.read(name)).hexdigest() for name in files}
    manifest = json.loads(archive.read(manifest_name))
    files = manifest.get("files")
    if not isinstance(files, list):
        raise TrustError("accepted release manifest has no file inventory")
    expected = {manifest_name}
    hashes: dict[str, str] = {}
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size"}:
            raise TrustError("accepted manifest entry schema mismatch")
        name = f"{root_name}/{entry['path']}"
        content = archive.read(name)
        if len(content) != entry["size"] or hashlib.sha256(content).hexdigest() != entry["sha256"]:
            raise TrustError(f"accepted manifest mismatch: {entry['path']}")
        expected.add(name)
        hashes[name] = entry["sha256"]
    if set(names) != expected:
        raise TrustError("accepted archive inventory differs from its manifest")
    return len(files), hashes


def inventory(candidate_root: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for phase, expected_hash in sorted(ACCEPTED_BASELINES.items(), key=lambda item: int(item[0])):
        archive_path = candidate_root / "outputs" / f"phase-{phase}.zip"
        if not archive_path.is_file() or sha256_file(archive_path) != expected_hash:
            raise TrustError(f"phase-{phase} accepted archive differs from the independent registry")
        with zipfile.ZipFile(archive_path) as archive:
            names = _safe_members(archive)
            archive_root = PurePosixPath(names[0]).parts[0]
            manifest_files, hashes = _verify_manifest(archive, names, archive_root)
            contracts = [
                {
                    "path": name,
                    "sha256": hashes.get(name, hashlib.sha256(archive.read(name)).hexdigest()),
                    "kind": contract_kind(name),
                }
                for name in sorted(names) if contract_kind(name) != "OTHER"
            ]
        executable = [contract for contract in contracts if contract["kind"] != "FIXTURE"]
        if phase != "0" and not executable:
            raise TrustError(f"phase-{phase} contains no immutable executable contracts")
        records.append(
            {
                "phase": phase,
                "archivePath": archive_path.relative_to(candidate_root).as_posix(),
                "archiveSha256": expected_hash,
                "archiveRoot": archive_root,
                "manifestFileCount": manifest_files,
                "contractCount": len(contracts),
                "contracts": contracts,
            }
        )
    return records


def _safe_extract(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        _safe_members(archive)
        for info in archive.infolist():
            target = (destination / PurePosixPath(info.filename)).resolve()
            try:
                target.relative_to(destination.resolve())
            except ValueError as error:
                raise TrustError("accepted archive extraction escapes the temporary root") from error
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output)


def _overlay_candidate_paths(accepted_root: Path, record: dict[str, Any], candidate_root: Path) -> dict[str, Any]:
    excluded = {
        "src/finance_cockpit/__init__.py": (
            "The public aggregator exports later accepted phases; current architecture/API gates validate it."
        )
    }
    with zipfile.ZipFile(candidate_root / record["archivePath"]) as archive:
        manifest_name = f"{record['archiveRoot']}/release-manifest.json"
        if manifest_name not in archive.namelist():
            return {"adapterId": "PHASE_SCOPED_HISTORICAL_PATHS_V1", "overlaidPaths": [], "excludedPaths": excluded}
        manifest = json.loads(archive.read(manifest_name))
        historical_paths = [entry["path"] for entry in manifest["files"]]
    overlaid: list[str] = []
    for relative in historical_paths:
        if relative in excluded or not relative.startswith(("src/", "supabase/", "golden_cases/")):
            continue
        source = candidate_root / relative
        if not source.is_file():
            raise TrustError(f"candidate removed a historical contract dependency: {relative}")
        destination = accepted_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        overlaid.append(relative)
    return {
        "adapterId": "PHASE_SCOPED_HISTORICAL_PATHS_V1",
        "overlaidPaths": sorted(overlaid),
        "excludedPaths": excluded,
    }


def _unittest_ids_from_zip(candidate_root: Path, phase: str, contract_path: str, relative: str) -> list[str]:
    module = relative[:-3].replace("/", ".")
    with zipfile.ZipFile(candidate_root / "outputs" / f"phase-{phase}.zip") as archive:
        source = archive.read(contract_path).decode("utf-8")
    tree = ast.parse(source, filename=contract_path)
    return sorted(
        f"{module}.{node.name}.{member.name}"
        for node in tree.body if isinstance(node, ast.ClassDef)
        for member in node.body
        if isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef)) and member.name.startswith("test_")
    )


def _probe_postgresql_restricted_cwd(
    *, cwd: Path, environment: dict[str, str], log_path: Path
) -> None:
    """Fail closed if PostgreSQL's restricted Windows child cannot use the exact contract CWD."""

    if os.name != "nt":
        return
    if environment.get("PG_RESTRICT_EXEC"):
        raise TrustError("PG_RESTRICT_EXEC bypass is forbidden")
    initdb = Path(environment["PHASE2_POSTGRES_BIN"]) / "initdb.exe"
    probe_data = Path(environment["TEMP"]) / "restricted-initdb-cwd-probe"
    shutil.rmtree(probe_data, ignore_errors=True)
    system_root = Path(os.environ["SystemRoot"])
    icacls = system_root / "System32" / "icacls.exe"
    acl = subprocess.run(
        [str(icacls), str(cwd)],
        cwd=system_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    try:
        probe = subprocess.run(
            [
                str(initdb),
                "-D",
                str(probe_data),
                "--username=postgres",
                "--auth=trust",
                "--encoding=UTF8",
                "--no-locale",
                "--no-sync",
            ],
            cwd=cwd,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    finally:
        shutil.rmtree(probe_data, ignore_errors=True)
    if probe.returncode != 0:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(
            f"restrictedPostgresCwd={cwd}\nACL:\n{acl.stdout}\nPROBE:\n{probe.stdout}",
            encoding="utf-8",
        )
        raise TrustError(
            f"accepted PostgreSQL contract CWD rejects the restricted child; log={log_path}"
        )


def _grant_restricted_postgres_temp_access(root: Path) -> None:
    """Restore the inherited Users ACE that Python's Windows 0o700 temp root removes."""

    if os.name != "nt":
        return
    system_root = Path(os.environ["SystemRoot"])
    icacls = system_root / "System32" / "icacls.exe"
    result = subprocess.run(
        [
            str(icacls),
            str(root),
            "/grant:r",
            "*S-1-5-32-545:(OI)(CI)M",
        ],
        cwd=system_root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if result.returncode != 0:
        raise TrustError(
            f"could not grant the restricted PostgreSQL child access to {root}: {result.stdout}"
        )


def execute(candidate_root: Path, log_root: Path) -> dict[str, Any]:
    records = inventory(candidate_root)
    snapshot = candidate_snapshot(candidate_root)
    executions: list[dict[str, Any]] = []
    adapters: list[dict[str, Any]] = []
    sequence = 0
    for record in records:
        phase = record["phase"]
        if phase == "0":
            continue
        with tempfile.TemporaryDirectory(prefix=f"trust-p{phase}-") as temp_name:
            temp_root = Path(temp_name)
            _grant_restricted_postgres_temp_access(temp_root)
            _safe_extract(candidate_root / record["archivePath"], temp_root)
            accepted_root = temp_root / record["archiveRoot"]
            adapter = _overlay_candidate_paths(accepted_root, record, candidate_root)
            adapter["baselinePhase"] = phase
            adapters.append(adapter)
            output_dir = accepted_root / "outputs"
            output_dir.mkdir(exist_ok=True)
            for accepted_phase in range(1, int(phase) + 1):
                archive = candidate_root / "outputs" / f"phase-{accepted_phase}.zip"
                if archive.is_file():
                    shutil.copy2(archive, output_dir / archive.name)
            for contract in record["contracts"]:
                if contract["kind"] == "FIXTURE":
                    continue
                sequence += 1
                relative = contract["path"].removeprefix(f"{record['archiveRoot']}/")
                if contract["kind"] == "UNITTEST":
                    module = relative[:-3].replace("/", ".")
                    logical = ["python", "-m", "unittest", "-v", module]
                    expected_ids = _unittest_ids_from_zip(candidate_root, phase, contract["path"], relative)
                else:
                    logical = ["python", relative]
                    expected_ids = None
                log_path = log_root / f"phase-{phase}-{sequence:03d}-{contract['kind'].lower()}.log"
                environment = candidate_environment(accepted_root)
                environment["PYTHONPATH"] = os.pathsep.join(
                    (environment["PYTHONPATH"], str(candidate_root))
                )
                if contract["kind"] == "POSTGRESQL":
                    environment["JUSTUS_TRUSTED_POSTGRES_PG_CTL"] = "1"
                    _probe_postgresql_restricted_cwd(
                        cwd=accepted_root,
                        environment=environment,
                        log_path=log_path,
                    )
                output = run_checked(
                    python_command(*logical[1:]),
                    cwd=accepted_root,
                    environment=environment,
                    log_path=log_path,
                    label=f"accepted {contract['kind']} contract {contract['path']}",
                )
                case_results = parse_case_results(contract["kind"], relative, output, expected_ids)
                executions.append(
                    {
                        "baselinePhase": phase,
                        "contractPath": contract["path"],
                        "contractSha256": contract["sha256"],
                        "kind": contract["kind"],
                        "command": logical,
                        "candidateSnapshot": snapshot,
                        "result": "PASS",
                        "exitCode": 0,
                        "logPath": log_path.relative_to(candidate_root).as_posix(),
                        "logSha256": sha256_file(log_path),
                        "caseResults": case_results,
                    }
                )
    expected_count = sum(
        1 for record in records for contract in record["contracts"] if contract["kind"] != "FIXTURE"
    )
    if len(executions) != expected_count or expected_count != 85:
        raise TrustError(f"immutable contract count mismatch: {len(executions)}/{expected_count}, expected 85")
    receipt = {
        "schemaVersion": "2",
        "status": "PASS",
        "mode": "EXECUTED_AGAINST_PHASE_SCOPED_CANDIDATE",
        "candidateSnapshot": snapshot,
        "temporaryExtractionPolicy": "OS_TEMP_SHORT_PATH_V1",
        "baselines": records,
        "compatibilityAdapters": adapters,
        "executions": executions,
    }
    receipt_path = candidate_root / "governance" / "evidence" / "receipts" / "accepted-regression.json"
    write_json(receipt_path, receipt)
    return receipt



