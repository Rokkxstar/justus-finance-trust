"""Independent Phase-5 execution, evidence production, packaging, and decision."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from trusted.accepted import execute as execute_accepted
from trusted.common import (
    ACCEPTED_BASELINES,
    ARCHIVE_ROOT,
    CANDIDATE_COMMIT,
    CANDIDATE_REPOSITORY,
    CANDIDATE_SNAPSHOT,
    PARENT_PHASE4_SHA256,
    PRODUCT_OWNER_LEDGER_SHA256,
    TrustError,
    candidate_environment,
    candidate_snapshot,
    declared_test_ids,
    governance_control_files,
    parse_case_results,
    python_command,
    require_fields,
    require_release_identity,
    restore_git_transport_bytes,
    run_checked,
    safe_archive_manifest,
    sha256_file,
    source_material_files,
    write_json,
)


PAR_PLANS = (
    {
        "executionId": "E-PY-BUDGETING", "kind": "UNITTEST", "contractPath": "tests/test_budgeting.py",
        "matrixIds": ["AM-IA-001","AM-IA-002","AM-TM-001","AM-TM-002","AM-TM-003","AM-TM-004","AM-VL-001","AM-VL-003","AM-VL-004","AM-PA-001","AM-PA-002","AM-PA-003","AM-PA-004","AM-PA-005","AM-DI-001","AM-DI-003","AM-IQ-001","AM-IQ-004","AM-FP-001","AM-FP-002","AM-FP-005"],
    },
    {
        "executionId": "E-PY-ARCHITECTURE", "kind": "UNITTEST", "contractPath": "tests/test_architecture_guardrails.py",
        "matrixIds": ["AM-IA-005","AM-PA-001","AM-PA-004","AM-IQ-004"],
    },
    {
        "executionId": "E-PY-GOVERNANCE", "kind": "UNITTEST", "contractPath": "tests/test_governance_retrofit.py",
        "matrixIds": ["AM-PA-001","AM-PA-004","AM-DI-001","AM-IQ-001","AM-IQ-004"],
    },
    {
        "executionId": "E-GOLDEN-PHASE5", "kind": "SCRIPT", "contractPath": "scripts/phase5_golden_cases.py",
        "matrixIds": ["AM-TM-002","AM-TM-004","AM-VL-004","AM-PA-001","AM-PA-003","AM-IQ-001","AM-FP-001","AM-FP-002","AM-FP-005"],
    },
    {
        "executionId": "E-POSTGRES-PHASE5", "kind": "SCRIPT", "contractPath": "scripts/phase5_postgres_tests.py",
        "matrixIds": ["AM-IA-001","AM-IA-002","AM-IA-005","AM-TM-001","AM-TM-003","AM-PA-002","AM-PA-005","AM-DI-003","AM-CA-001","AM-CA-003","AM-FP-002"],
    },
    {
        "executionId": "E-ARCHITECTURE-PHASE5", "kind": "SCRIPT", "contractPath": "scripts/check_architecture.py",
        "matrixIds": ["AM-IA-005","AM-PA-001","AM-PA-004","AM-IQ-004"],
    },
)

GOLDEN_RUNNERS = (
    ("scripts/golden_cases.py", 4),
    ("scripts/phase2_golden_cases.py", 2),
    ("scripts/phase3_golden_cases.py", 9),
    ("scripts/phase4_golden_cases.py", 7),
    ("scripts/phase5_golden_cases.py", 3),
)
POSTGRES_RUNNERS = (
    ("scripts/phase2_postgres_tests.py", 73),
    ("scripts/phase3_postgres_tests.py", 196),
    ("scripts/phase4_postgres_tests.py", 71),
    ("scripts/phase5_postgres_tests.py", 70),
)
EXPECTED_UNIT_TESTS = 228
MIN_LINE_COVERAGE = 98.20
MIN_BRANCH_COVERAGE = 95.38
MIN_FUNCTION_COVERAGE = 100.0


def _trusted_files(root: Path) -> tuple[Path, ...]:
    return tuple(sorted(path for path in (root / "trusted").rglob("*.py") if path.is_file()))


def _hashes(paths: tuple[Path, ...], root: Path) -> dict[str, str]:
    return {path.relative_to(root).as_posix(): sha256_file(path) for path in paths}


def _all_unit_test_ids(root: Path) -> list[str]:
    identifiers: list[str] = []
    for path in sorted((root / "tests").glob("test_*.py")):
        # unittest discovery adds the tests directory to sys.path, so emitted
        # IDs begin with test_module rather than tests.test_module.
        module = path.stem
        identifiers.extend(declared_test_ids(path, module))
    if len(identifiers) != len(set(identifiers)):
        raise TrustError("candidate unit-test source contains duplicate IDs")
    return sorted(identifiers)


def _coverage_metrics(data: dict[str, Any]) -> dict[str, Any]:
    totals = data["totals"]
    line = 100.0 if totals["num_statements"] == 0 else totals["covered_lines"] * 100.0 / totals["num_statements"]
    branch = 100.0 if totals["num_branches"] == 0 else totals["covered_branches"] * 100.0 / totals["num_branches"]
    total_functions = 0
    covered_functions = 0
    module_failures: list[str] = []
    for filename, details in sorted(data["files"].items()):
        summary = details["summary"]
        module_line = 100.0 if summary["num_statements"] == 0 else summary["covered_lines"] * 100.0 / summary["num_statements"]
        module_branch = 100.0 if summary["num_branches"] == 0 else summary["covered_branches"] * 100.0 / summary["num_branches"]
        if module_line < 90.0 or module_branch < 85.0:
            module_failures.append(f"{filename}:{module_line:.2f}/{module_branch:.2f}")
        for name, region in details.get("functions", {}).items():
            function_summary = region["summary"]
            if name and function_summary["num_statements"]:
                total_functions += 1
                if function_summary["covered_lines"] > 0:
                    covered_functions += 1
    function = 100.0 if total_functions == 0 else covered_functions * 100.0 / total_functions
    if line < MIN_LINE_COVERAGE or branch < MIN_BRANCH_COVERAGE or function < MIN_FUNCTION_COVERAGE or module_failures:
        raise TrustError(
            f"coverage gate failed: lines={line:.2f}, branches={branch:.2f}, functions={function:.2f}, "
            f"moduleFailures={module_failures}"
        )
    return {
        "linesPercent": round(line, 2),
        "branchesPercent": round(branch, 2),
        "functionsPercent": round(function, 2),
        "coveredFunctions": covered_functions,
        "totalFunctions": total_functions,
    }


def run_current_quality(candidate_root: Path, log_root: Path) -> dict[str, Any]:
    environment = candidate_environment(candidate_root)
    all_ids = _all_unit_test_ids(candidate_root)
    if len(all_ids) != EXPECTED_UNIT_TESTS:
        raise TrustError(f"candidate declares {len(all_ids)} unit tests; expected {EXPECTED_UNIT_TESTS}")
    run_checked(
        python_command("-m", "coverage", "erase"), cwd=candidate_root, environment=environment,
        log_path=log_root / "coverage-erase.log", label="coverage reset",
    )
    unit_output = run_checked(
        python_command("-m", "coverage", "run", "--branch", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py", "-v"),
        cwd=candidate_root, environment=environment, log_path=log_root / "unit-tests.log", label="full unit suite",
    )
    unit_cases = parse_case_results("UNITTEST", "tests/test_*.py", unit_output, all_ids)
    coverage_path = log_root / "coverage.json"
    run_checked(
        python_command("-m", "coverage", "json", "-o", str(coverage_path)), cwd=candidate_root, environment=environment,
        log_path=log_root / "coverage-json.log", label="coverage JSON export",
    )
    coverage = _coverage_metrics(json.loads(coverage_path.read_text(encoding="utf-8")))

    golden_counts: dict[str, int] = {}
    for index, (relative, expected_count) in enumerate(GOLDEN_RUNNERS, 1):
        output = run_checked(
            python_command(relative), cwd=candidate_root, environment=environment,
            log_path=log_root / f"golden-{index}.log", label=relative,
        )
        cases = parse_case_results("GOLDEN", relative, output)
        if len(cases) != expected_count:
            raise TrustError(f"{relative}: {len(cases)} Golden cases, expected {expected_count}")
        golden_counts[relative] = len(cases)

    architecture_output = run_checked(
        python_command("scripts/check_architecture.py"), cwd=candidate_root, environment=environment,
        log_path=log_root / "architecture.log", label="architecture guardrails",
    )
    parse_case_results("ARCHITECTURE", "scripts/check_architecture.py", architecture_output)
    ci_output = run_checked(
        python_command("-m", "scripts.ci_self_test"), cwd=candidate_root, environment=environment,
        log_path=log_root / "ci-self-test.log", label="CI negative self-test",
    )
    parse_case_results("ARCHITECTURE", "scripts/ci_self_test.py", ci_output)

    postgres_counts: dict[str, int] = {}
    for index, (relative, expected_count) in enumerate(POSTGRES_RUNNERS, 1):
        output = run_checked(
            python_command(relative), cwd=candidate_root, environment=environment,
            log_path=log_root / f"postgres-{index}.log", label=relative,
        )
        cases = parse_case_results("POSTGRESQL", relative, output)
        if len(cases) != expected_count:
            raise TrustError(f"{relative}: {len(cases)} PostgreSQL cases, expected {expected_count}")
        postgres_counts[relative] = len(cases)
    return {
        "unitTests": len(unit_cases),
        "coverage": coverage,
        "goldenCases": golden_counts,
        "goldenTotal": sum(golden_counts.values()),
        "postgresCases": postgres_counts,
        "postgresTotal": sum(postgres_counts.values()),
        "architecture": "PASS",
        "ciNegativeSelfTest": "PASS",
    }


def run_par(candidate_root: Path, log_root: Path, generated_at: str) -> dict[str, Any]:
    environment = candidate_environment(candidate_root)
    executions: list[dict[str, Any]] = []
    for plan in PAR_PLANS:
        relative = plan["contractPath"]
        contract = candidate_root / relative
        if plan["kind"] == "UNITTEST":
            module = relative[:-3].replace("/", ".")
            logical = ["python", "-m", "unittest", "-v", module]
            test_ids = declared_test_ids(contract, module)
        else:
            logical = ["python", relative]
            test_ids = [f"SCRIPT:{relative}"]
        log_path = log_root / f"{plan['executionId'].lower()}.log"
        output = run_checked(
            python_command(*logical[1:]), cwd=candidate_root, environment=environment,
            log_path=log_path, label=f"PAR {plan['executionId']}",
        )
        cases = parse_case_results(plan["kind"], relative, output, test_ids if plan["kind"] == "UNITTEST" else None)
        executions.append(
            {
                "executionId": plan["executionId"],
                "kind": plan["kind"],
                "command": logical,
                "contractPath": relative,
                "contractSha256": sha256_file(contract),
                "testIds": test_ids,
                "caseResults": cases,
                "matrixIds": plan["matrixIds"],
                "artifactPath": log_path.relative_to(candidate_root).as_posix(),
                "artifactSha256": sha256_file(log_path),
                "exitCode": 0,
                "result": "PASS",
            }
        )
    snapshot = candidate_snapshot(candidate_root)
    receipt = {
        "schemaVersion": "1",
        "receiptId": f"PHASE5-PAR-RECEIPT-{CANDIDATE_SNAPSHOT[:12]}",
        "status": "PASS",
        "generatedAt": generated_at,
        "sourceSnapshot": snapshot,
        "authority": {
            "executorId": "FINANCE-CI-FULL-EXIT",
            "provider": "GITHUB_ACTIONS",
            "runId": os.environ.get("GITHUB_RUN_ID", "local-trusted-dry-run"),
            "actor": os.environ.get("GITHUB_ACTOR", "local-trusted-runner"),
            "repository": os.environ.get("GITHUB_REPOSITORY", "Rokkxstar/justus-finance-trust"),
            "commitSha": os.environ.get("GITHUB_SHA", "local-trusted-dry-run"),
        },
        "executions": executions,
    }
    receipt_path = candidate_root / "governance" / "evidence" / "receipts" / "phase5-par-execution.json"
    write_json(receipt_path, receipt)
    return receipt


def bind_review_documents(candidate_root: Path, par_receipt: dict[str, Any], accepted_receipt: dict[str, Any], generated_at: str) -> None:
    par_path = candidate_root / "governance" / "evidence" / "phase-5-pre-exit-adversarial-review.json"
    par = json.loads(par_path.read_text(encoding="utf-8"))
    require_fields(
        par,
        {"schemaVersion","reviewId","status","phase","reviewer","reviewedAt","parentAcceptedBaselineSha256",
         "reviewedPreRetrofitCandidateSha256","reviewedSourceSnapshot","impactDeclaration","matrix","executionReceipt",
         "dispositions","findings","transitionStatement"},
        "PAR record",
    )
    par["reviewer"] = {"executorId": "FINANCE-CI-FULL-EXIT", "role": "INTERNAL_ADVERSARIAL_REVIEWER"}
    par["reviewedAt"] = generated_at
    receipt_path = candidate_root / "governance" / "evidence" / "receipts" / "phase5-par-execution.json"
    par["executionReceipt"] = {
        "receiptId": par_receipt["receiptId"],
        "path": receipt_path.relative_to(candidate_root).as_posix(),
        "sha256": sha256_file(receipt_path),
    }
    write_json(par_path, par)

    acceptance_path = candidate_root / "governance" / "acceptance-contracts" / "phase-5.json"
    acceptance = json.loads(acceptance_path.read_text(encoding="utf-8"))
    required_gates = acceptance.get("requiredGates")
    if not isinstance(required_gates, list) or not required_gates:
        raise TrustError("acceptance contract has no required gates")
    accepted_path = candidate_root / "governance" / "evidence" / "receipts" / "accepted-regression.json"
    self_review = {
        "acceptanceContractSha256": sha256_file(acceptance_path),
        "acceptedRegressionReceiptSha256": sha256_file(accepted_path),
        "errorClassesExamined": [
            "Household and owner isolation across raw, derived, nested and audit paths",
            "Point-in-time, timezone, policy-effective and provenance chronology boundaries",
            "Repository authority, attestations, status and calculation fingerprint integrity",
            "Lineage, duplicate identity, correction and current-resolver closure",
            "Concurrency, rollback, append-only and non-negative balance atomicity",
            "Double counting, personal protection and nonmaterial-input financial safety",
        ],
        "findings": [],
        "gateResults": {gate: "PASS" for gate in required_gates},
        "knownBlockers": [],
        "parReceiptSha256": sha256_file(receipt_path),
        "reviewId": f"PHASE5-SELF-REVIEW-{CANDIDATE_SNAPSHOT[:12]}",
        "reviewedAt": generated_at,
        "schemaVersion": "1",
        "scopeClean": True,
        "sourceSnapshot": candidate_snapshot(candidate_root),
        "status": "PASS",
    }
    write_json(candidate_root / "governance" / "evidence" / "phase-5-self-review.json", self_review)


def verify_generated_evidence(candidate_root: Path, accepted: dict[str, Any], par: dict[str, Any]) -> None:
    """Bind every generated receipt and case result back to trusted memory/logs."""

    accepted_path = candidate_root / "governance" / "evidence" / "receipts" / "accepted-regression.json"
    par_path = candidate_root / "governance" / "evidence" / "receipts" / "phase5-par-execution.json"
    if json.loads(accepted_path.read_text(encoding="utf-8")) != accepted:
        raise TrustError("accepted-regression receipt changed after trusted generation")
    if json.loads(par_path.read_text(encoding="utf-8")) != par:
        raise TrustError("PAR receipt changed after trusted generation")
    roots = {record["phase"]: record["archiveRoot"] for record in accepted["baselines"]}
    for execution in accepted["executions"]:
        log = candidate_root / execution["logPath"]
        if not log.is_file() or sha256_file(log) != execution["logSha256"]:
            raise TrustError("accepted-regression log changed after trusted execution")
        relative = execution["contractPath"].removeprefix(f"{roots[execution['baselinePhase']]}/")
        expected = [item["caseId"] for item in execution["caseResults"]] if execution["kind"] == "UNITTEST" else None
        parsed = parse_case_results(execution["kind"], relative, log.read_text(encoding="utf-8"), expected)
        if parsed != execution["caseResults"]:
            raise TrustError("accepted-regression structured cases changed after trusted execution")
    for execution in par["executions"]:
        log = candidate_root / execution["artifactPath"]
        if not log.is_file() or sha256_file(log) != execution["artifactSha256"]:
            raise TrustError("PAR log changed after trusted execution")
        expected = execution["testIds"] if execution["kind"] == "UNITTEST" else None
        parsed = parse_case_results(execution["kind"], execution["contractPath"], log.read_text(encoding="utf-8"), expected)
        if parsed != execution["caseResults"]:
            raise TrustError("PAR structured cases changed after trusted execution")


def validate_packaged_candidate(archive_path: Path, candidate_root: Path, release_identity: str) -> dict[str, Any]:
    manifest = safe_archive_manifest(archive_path)
    require_fields(
        manifest,
        {"schemaVersion","releaseIdentity","phase","sourceDate","archiveRoot","predecessorAcceptedBaselineSha256",
         "sourceSnapshot","impactDeclarationId","impactDeclarationSha256","parSha256","productOwnerTrustLedgerSha256",
         "files","evidenceReceipts","acceptanceContractId","acceptanceContractSha256","selfReviewSha256"},
        "release manifest",
    )
    if (
        manifest["schemaVersion"] != "2" or manifest["phase"] != "5" or manifest["archiveRoot"] != ARCHIVE_ROOT
        or manifest["releaseIdentity"] != release_identity
        or manifest["predecessorAcceptedBaselineSha256"] != PARENT_PHASE4_SHA256
        or manifest["productOwnerTrustLedgerSha256"] != PRODUCT_OWNER_LEDGER_SHA256
        or manifest["sourceSnapshot"]["combinedSha256"] != CANDIDATE_SNAPSHOT
    ):
        raise TrustError("release manifest identity/trust binding mismatch")
    entries = {entry["path"]: entry for entry in manifest["files"]}
    required_paths = set()
    for path in (*source_material_files(candidate_root), *governance_control_files(candidate_root)):
        relative = path.relative_to(candidate_root).as_posix()
        required_paths.add(relative)
        entry = entries.get(relative)
        if entry is None or entry["sha256"] != sha256_file(path) or entry["size"] != path.stat().st_size:
            raise TrustError(f"packaged source/control differs from checkout: {relative}")
    for phase, expected in ACCEPTED_BASELINES.items():
        relative = f"outputs/phase-{phase}.zip"
        entry = entries.get(relative)
        if entry is None or entry["sha256"] != expected:
            raise TrustError(f"release does not contain the accepted phase-{phase} archive")
        required_paths.add(relative)
    for relative in (
        "governance/evidence/receipts/phase5-par-execution.json",
        "governance/evidence/receipts/accepted-regression.json",
        "governance/evidence/phase-5-pre-exit-adversarial-review.json",
        "governance/evidence/phase-5-self-review.json",
    ):
        path = candidate_root / relative
        entry = entries.get(relative)
        if entry is None or entry["sha256"] != sha256_file(path):
            raise TrustError(f"release evidence binding mismatch: {relative}")
        required_paths.add(relative)
    receipts = (
        json.loads((candidate_root / "governance/evidence/receipts/phase5-par-execution.json").read_text(encoding="utf-8")),
        json.loads((candidate_root / "governance/evidence/receipts/accepted-regression.json").read_text(encoding="utf-8")),
    )
    for receipt in receipts:
        for execution in receipt["executions"]:
            relative = execution.get("artifactPath", execution.get("logPath"))
            expected_hash = execution.get("artifactSha256", execution.get("logSha256"))
            entry = entries.get(relative)
            if entry is None or entry["sha256"] != expected_hash:
                raise TrustError(f"release omits or changes an execution log: {relative}")
    if "outputs/phase-5.zip" in entries:
        raise TrustError("release archive recursively contains an unaccepted Phase-5 archive")
    if not required_paths <= set(entries):
        raise TrustError("release manifest omits trusted required paths")
    return manifest


def _fresh_extract_quality(archive_path: Path, log_root: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="trust-fresh-") as temp_name:
        temp_root = Path(temp_name)
        with zipfile.ZipFile(archive_path) as archive:
            for info in archive.infolist():
                target = (temp_root / info.filename).resolve()
                try:
                    target.relative_to(temp_root.resolve())
                except ValueError as error:
                    raise TrustError("fresh-extract path escaped the temporary directory") from error
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("wb") as destination:
                        shutil.copyfileobj(source, destination)
        extracted = temp_root / ARCHIVE_ROOT
        candidate_snapshot(extracted)
        return run_current_quality(extracted, log_root)


def build_candidate(candidate_root: Path, output: Path, release_identity: str, log_path: Path) -> None:
    run_checked(
        python_command("scripts/build_phase5_release.py", "--output", str(output), "--release-identity", release_identity),
        cwd=candidate_root, environment=candidate_environment(candidate_root), log_path=log_path,
        label="candidate deterministic archive builder",
    )


def _iso_utc(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrustError("generated-at must be an ISO-8601 timestamp") from error
    if parsed.utcoffset() is None:
        raise TrustError("generated-at must include a timezone")
    return parsed.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--release-identity", required=True)
    parser.add_argument("--generated-at")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--trust-root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    candidate_root = args.candidate.resolve()
    output_dir = args.output_dir.resolve()
    trust_root = args.trust_root.resolve()
    generated_at = _iso_utc(args.generated_at)
    require_release_identity(args.release_identity)
    if not candidate_root.is_dir() or candidate_root == trust_root:
        raise TrustError("candidate checkout must be a separate directory")
    original_trust_hashes = _hashes(_trusted_files(trust_root), trust_root)
    restore_git_transport_bytes(candidate_root)
    snapshot = candidate_snapshot(candidate_root)
    ledger_hash = sha256_file(candidate_root / "governance" / "product-owner-trust-ledger.json")
    if ledger_hash != PRODUCT_OWNER_LEDGER_SHA256:
        raise TrustError("candidate ledger differs from the independent compiled trust anchor")
    if os.environ.get("FINANCE_PO_TRUST_LEDGER_SHA256", "").lower() != PRODUCT_OWNER_LEDGER_SHA256:
        raise TrustError("protected Product-Owner ledger trust anchor is unavailable")

    logs = candidate_root / "governance" / "evidence" / "logs"
    # Produce externally executed receipts first. The full current suite then
    # validates those exact receipts and their bindings instead of the
    # transport-normalized bootstrap evidence from the candidate checkout.
    accepted = execute_accepted(candidate_root, logs / "accepted")
    par = run_par(candidate_root, logs, generated_at)
    bind_review_documents(candidate_root, par, accepted, generated_at)
    candidate_snapshot(candidate_root)
    quality = run_current_quality(candidate_root, logs / "trusted-current")

    governance_env = candidate_environment(candidate_root)
    for index, command in enumerate(
        (
            python_command("scripts/check_governance.py"),
            python_command("scripts/golden_profiles.py"),
            python_command("-m", "scripts.acceptance_contract"),
        ),
        1,
    ):
        run_checked(command, cwd=candidate_root, environment=governance_env, log_path=logs / f"trusted-governance-{index}.log", label="candidate contract compatibility")

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_one = output_dir / f"{args.release_identity}.zip"
    archive_two = output_dir / f"{args.release_identity}.rebuild.zip"
    build_candidate(candidate_root, archive_one, args.release_identity, output_dir / "trusted-build-1.log")
    build_candidate(candidate_root, archive_two, args.release_identity, output_dir / "trusted-build-2.log")
    if archive_one.read_bytes() != archive_two.read_bytes():
        raise TrustError("two clean candidate archive builds are not byte-identical")
    archive_two.unlink()
    manifest = validate_packaged_candidate(archive_one, candidate_root, args.release_identity)
    fresh_quality = _fresh_extract_quality(archive_one, output_dir / "fresh-extract-logs")
    if fresh_quality != quality:
        raise TrustError("fresh-extract quality results differ from the original candidate run")
    if _hashes(_trusted_files(trust_root), trust_root) != original_trust_hashes:
        raise TrustError("candidate execution modified the independent trust implementation")
    sentinel = os.environ.get("FORGED_GH_SENTINEL")
    if sentinel and Path(sentinel).exists():
        raise TrustError("a candidate-controlled command invoked the forged gh sentinel")

    verify_generated_evidence(candidate_root, accepted, par)
    manifest = validate_packaged_candidate(archive_one, candidate_root, args.release_identity)

    decision = {
        "schemaVersion": "1",
        "status": "PASS",
        "generatedAt": generated_at,
        "trustRepository": os.environ.get("GITHUB_REPOSITORY", "Rokkxstar/justus-finance-trust"),
        "trustCommit": os.environ.get("GITHUB_SHA", "local-trusted-dry-run"),
        "candidateRepository": CANDIDATE_REPOSITORY,
        "candidateCommit": CANDIDATE_COMMIT,
        "candidateSnapshot": snapshot,
        "productOwnerLedgerSha256": PRODUCT_OWNER_LEDGER_SHA256,
        "releaseIdentity": args.release_identity,
        "releaseFile": archive_one.name,
        "releaseSha256": sha256_file(archive_one),
        "manifestFileCount": len(manifest["files"]),
        "quality": quality,
        "acceptedRegressionExecutions": len(accepted["executions"]),
        "parExecutions": len(par["executions"]),
        "freshExtract": "PASS",
        "fakeGhBoundary": "PASS",
        "scope": "PHASE_5_ONLY",
    }
    decision_path = output_dir / "phase-5-trust-decision.json"
    write_json(decision_path, decision)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"release_sha256={decision['releaseSha256']}\n")
            handle.write(f"decision_sha256={sha256_file(decision_path)}\n")
    print(f"TRUSTED PHASE-5 EXIT: PASS ({decision['releaseSha256']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
