"""Fresh-runner verification before GitHub provenance attestation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from trusted.common import (
    ACCEPTED_BASELINES,
    ARCHIVE_ROOT,
    CANDIDATE_COMMIT,
    CANDIDATE_REPOSITORY,
    CANDIDATE_SNAPSHOT,
    PRODUCT_OWNER_LEDGER_SHA256,
    TrustError,
    candidate_snapshot,
    require_fields,
    require_release_identity,
    safe_archive_manifest,
    sha256_file,
)


DECISION_FIELDS = {
    "schemaVersion","status","generatedAt","trustRepository","trustCommit","candidateRepository",
    "candidateCommit","candidateSnapshot","productOwnerLedgerSha256","releaseIdentity","releaseFile",
    "releaseSha256","manifestFileCount","quality","acceptedRegressionExecutions","parExecutions",
    "freshExtract","fakeGhBoundary","scope",
}


def verify(directory: Path, expected_release_sha256: str | None = None, expected_decision_sha256: str | None = None) -> tuple[Path, Path]:
    decision_path = directory / "phase-5-trust-decision.json"
    if not decision_path.is_file():
        raise TrustError("trusted decision is missing")
    if expected_decision_sha256 and sha256_file(decision_path) != expected_decision_sha256:
        raise TrustError("trusted decision differs from the immutable verification-job output")
    decision = json.loads(decision_path.read_text(encoding="utf-8"))
    require_fields(decision, DECISION_FIELDS, "trusted decision")
    expected_repository = os.environ.get("GITHUB_REPOSITORY", "Rokkxstar/justus-finance-trust")
    expected_commit = os.environ.get("GITHUB_SHA", "local-trusted-dry-run")
    if (
        decision["schemaVersion"] != "1" or decision["status"] != "PASS"
        or decision["trustRepository"] != expected_repository or decision["trustCommit"] != expected_commit
        or decision["candidateRepository"] != CANDIDATE_REPOSITORY or decision["candidateCommit"] != CANDIDATE_COMMIT
        or decision["candidateSnapshot"].get("combinedSha256") != CANDIDATE_SNAPSHOT
        or decision["productOwnerLedgerSha256"] != PRODUCT_OWNER_LEDGER_SHA256
        or decision["acceptedRegressionExecutions"] != 85 or decision["parExecutions"] != 6
        or decision["freshExtract"] != "PASS" or decision["fakeGhBoundary"] != "PASS"
        or decision["scope"] != "PHASE_5_ONLY"
    ):
        raise TrustError("trusted decision identity or required gate result mismatch")
    require_release_identity(decision["releaseIdentity"])
    release_path = directory / decision["releaseFile"]
    if not release_path.is_file() or sha256_file(release_path) != decision["releaseSha256"]:
        raise TrustError("release artifact hash differs from the trusted decision")
    if expected_release_sha256 and sha256_file(release_path) != expected_release_sha256:
        raise TrustError("release differs from the immutable verification-job output")
    manifest = safe_archive_manifest(release_path)
    if (
        manifest.get("releaseIdentity") != decision["releaseIdentity"]
        or manifest.get("sourceSnapshot", {}).get("combinedSha256") != CANDIDATE_SNAPSHOT
        or manifest.get("productOwnerTrustLedgerSha256") != PRODUCT_OWNER_LEDGER_SHA256
        or len(manifest.get("files", [])) != decision["manifestFileCount"]
    ):
        raise TrustError("release manifest differs from the trusted decision")
    entries = {entry["path"]: entry for entry in manifest["files"]}
    for phase, expected in ACCEPTED_BASELINES.items():
        if entries.get(f"outputs/phase-{phase}.zip", {}).get("sha256") != expected:
            raise TrustError(f"attestation candidate lacks accepted phase-{phase} baseline")
    quality = decision["quality"]
    if (
        quality.get("unitTests") != 228 or quality.get("goldenTotal") != 25 or quality.get("postgresTotal") != 410
        or quality.get("architecture") != "PASS" or quality.get("ciNegativeSelfTest") != "PASS"
        or quality.get("coverage", {}).get("linesPercent", 0) < 98.20
        or quality.get("coverage", {}).get("branchesPercent", 0) < 95.38
        or quality.get("coverage", {}).get("functionsPercent") != 100.0
    ):
        raise TrustError("attestation candidate quality metrics are incomplete")
    with tempfile.TemporaryDirectory(prefix="trust-attest-") as temp_name:
        temp_root = Path(temp_name)
        with zipfile.ZipFile(release_path) as archive:
            for info in archive.infolist():
                target = (temp_root / info.filename).resolve()
                try:
                    target.relative_to(temp_root.resolve())
                except ValueError as error:
                    raise TrustError("attestation extraction escapes the temporary root") from error
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as source, target.open("wb") as output:
                        shutil.copyfileobj(source, output)
        extracted = temp_root / ARCHIVE_ROOT
        candidate_snapshot(extracted)
        if sha256_file(extracted / "governance" / "product-owner-trust-ledger.json") != PRODUCT_OWNER_LEDGER_SHA256:
            raise TrustError("packaged Product-Owner ledger differs from the trust anchor")
    return release_path, decision_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--expected-release-sha256")
    parser.add_argument("--expected-decision-sha256")
    args = parser.parse_args()
    release, decision = verify(
        args.artifact_dir.resolve(), args.expected_release_sha256, args.expected_decision_sha256,
    )
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as handle:
            handle.write(f"release_path={release}\n")
            handle.write(f"decision_path={decision}\n")
            handle.write(f"release_sha256={sha256_file(release)}\n")
    print(f"PRE-ATTESTATION VERIFICATION: PASS ({sha256_file(release)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
