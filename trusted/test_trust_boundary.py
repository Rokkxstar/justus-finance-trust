"""Fast negative tests for the independent trust implementation itself."""

from __future__ import annotations

import os
import hashlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from trusted.common import (
    ACCEPTED_BASELINES,
    CANDIDATE_COMMIT,
    CANDIDATE_SNAPSHOT,
    PRODUCT_OWNER_LEDGER_SHA256,
    TRUSTED_RUNTIME_SUPPORT,
    TrustError,
    candidate_environment,
    governance_control_files,
    require_release_identity,
    restore_git_transport_bytes,
    safe_archive_manifest,
)
from trusted.phase5_exit import _contract_environment


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "phase5-external-trust.yml"


class TrustBoundaryTests(unittest.TestCase):
    def test_compiled_identities_are_full_hashes(self) -> None:
        self.assertRegex(CANDIDATE_COMMIT, r"^[0-9a-f]{40}$")
        for value in [CANDIDATE_SNAPSHOT, PRODUCT_OWNER_LEDGER_SHA256, *ACCEPTED_BASELINES.values()]:
            self.assertRegex(value, r"^[0-9a-f]{64}$")

    def test_release_identity_is_bound_to_snapshot_not_user_supplied_suffix(self) -> None:
        require_release_identity("phase-5-exit-20260828T000000Z-83f99826170b")
        with self.assertRaises(TrustError):
            require_release_identity("phase-5-exit-20260828T000000Z-8331052ea926")

    def test_workflow_actions_are_immutable_full_commit_pins(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        uses = re.findall(r"^\s*uses:\s*([^\s]+)\s*$", text, flags=re.MULTILINE)
        self.assertGreaterEqual(len(uses), 9)
        for reference in uses:
            self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$")

    def test_workflow_pins_candidate_and_does_not_use_gh_for_evidence(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn(f"ref: {CANDIDATE_COMMIT}", text)
        self.assertEqual(text.count("secrets.JUSTUS_READ_TOKEN"), 1)
        self.assertNotRegex(text, r"(?im)^\s*(?:run:\s*)?gh(?:\.exe)?\s")
        self.assertNotIn("gh run download", text.lower())
        self.assertIn("forged-gh-tripwire", text)
        self.assertIn("git config --global core.autocrlf false", text)

    def test_workflow_prepares_acl_bound_postgres_runtime_and_contract_workspace(self) -> None:
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("Prepare ACL-bound PostgreSQL contract workspace", text)
        self.assertIn('Join-Path $env:SystemDrive "justus-postgresql-$env:GITHUB_RUN_ID"', text)
        self.assertIn('Join-Path $env:SystemDrive "justus-pg-contracts-$env:GITHUB_RUN_ID"', text)
        self.assertNotIn("Join-Path $env:RUNNER_TEMP 'trusted-postgresql'", text)
        self.assertNotIn("Join-Path $env:RUNNER_TEMP 'trusted-contract-work'", text)
        self.assertIn("System32\\icacls.exe", text)
        self.assertEqual(text.count('"*${userSid}:(OI)(CI)F"'), 2)
        self.assertEqual(text.count('"*S-1-5-32-545:(OI)(CI)M"'), 1)
        self.assertIn('"TMPDIR=$contractTemp"', text)
        self.assertIn('"TEMP=$contractTemp"', text)
        self.assertIn('"TMP=$contractTemp"', text)
        self.assertNotIn("TEMP: ${{ runner.temp }}", text)
        self.assertIn("Prove restricted PostgreSQL child can use contract workspace", text)
        self.assertIn('$env:PHASE2_POSTGRES_BIN\\postgres.exe" -V', text)
        self.assertNotIn("PG_RESTRICT_EXEC", text)
        self.assertIn("Emit fail-closed accepted-contract diagnostic", text)
        self.assertIn("Get-Content -LiteralPath $diagnostic -Raw", text)

    def test_trusted_python_never_executes_a_gh_command(self) -> None:
        for path in sorted((ROOT / "trusted").glob("*.py")):
            if path.name == Path(__file__).name:
                continue
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(source, r"(?s)(?:subprocess\.run|run_checked)\([^\)]*['\"]gh(?:\.exe)?['\"]")

    def test_accepted_postgresql_contract_probes_exact_restricted_cwd(self) -> None:
        source = (ROOT / "trusted" / "accepted.py").read_text(encoding="utf-8")
        self.assertIn("_probe_postgresql_restricted_cwd", source)
        self.assertIn("str(initdb)", source)
        self.assertIn('"--no-sync"', source)
        self.assertIn("cwd=accepted_root", source)
        self.assertIn("PG_RESTRICT_EXEC bypass is forbidden", source)
        self.assertIn("restrictedPostgresCwd=", source)
        self.assertIn("_grant_restricted_postgres_temp_access", source)
        self.assertIn('"*S-1-5-32-545:(OI)(CI)M"', source)
        execute_source = source[source.index("def execute") :]
        self.assertLess(
            execute_source.index("_grant_restricted_postgres_temp_access(temp_root)"),
            execute_source.index("_safe_extract("),
        )

    def test_module_boot_does_not_trigger_path_hijacked_gh(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            sentinel = directory / "called.txt"
            (directory / "gh.cmd").write_text(f"@echo off\ntype nul > \"{sentinel}\"\nexit /b 93\n", encoding="ascii")
            environment = os.environ.copy()
            environment["PATH"] = os.pathsep.join((str(directory), environment.get("PATH", "")))
            environment["FORGED_GH_SENTINEL"] = str(sentinel)
            result = subprocess.run(
                [sys.executable, "-m", "trusted.phase5_exit", "--help"],
                cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertFalse(sentinel.exists())

    def test_governance_snapshot_excludes_mutable_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "governance" / "evidence").mkdir(parents=True)
            (root / "governance" / "stable.json").write_text("{}", encoding="utf-8")
            (root / "governance" / "evidence" / "receipt.json").write_text("{}", encoding="utf-8")
            selected = {path.relative_to(root).as_posix() for path in governance_control_files(root)}
            self.assertEqual(selected, {"governance/stable.json"})

    def test_candidate_environment_cannot_reach_workflow_command_files(self) -> None:
        with patch.dict(
            os.environ,
            {
                "PHASE2_POSTGRES_BIN": str(ROOT),
                "GITHUB_OUTPUT": "secret-output-path",
                "GITHUB_ENV": "secret-env-path",
                "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "secret-oidc-token",
                "FINANCE_PO_TRUST_LEDGER_SHA256": PRODUCT_OWNER_LEDGER_SHA256,
                "FORGED_GH_SENTINEL": "tripwire",
            },
            clear=True,
        ):
            environment = candidate_environment(ROOT)
        self.assertNotIn("GITHUB_OUTPUT", environment)
        self.assertNotIn("GITHUB_ENV", environment)
        self.assertNotIn("ACTIONS_ID_TOKEN_REQUEST_TOKEN", environment)
        self.assertNotIn("FINANCE_PO_TRUST_LEDGER_SHA256", environment)
        self.assertEqual(environment["FORGED_GH_SENTINEL"], "tripwire")
        self.assertEqual(
            Path(environment["PYTHONPATH"].split(os.pathsep)[0]),
            TRUSTED_RUNTIME_SUPPORT,
        )

    def test_trusted_runtime_repairs_nested_windows_temp_acls_without_bypass(self) -> None:
        source = (TRUSTED_RUNTIME_SUPPORT / "sitecustomize.py").read_text(encoding="utf-8")
        self.assertIn("_original_mkdtemp", source)
        self.assertIn("tempfile.mkdtemp = _restricted_postgres_compatible_mkdtemp", source)
        self.assertIn('"*S-1-5-32-545:(OI)(CI)M"', source)
        self.assertNotIn("PG_RESTRICT_EXEC", source)
        accepted = (ROOT / "trusted" / "accepted.py").read_text(encoding="utf-8")
        self.assertIn('(environment["PYTHONPATH"], str(candidate_root))', accepted)
        with patch.dict(
            os.environ,
            {
                "PHASE2_POSTGRES_BIN": str(ROOT),
                "SystemRoot": os.environ["SystemRoot"],
                "TEMP": tempfile.gettempdir(),
                "TMP": tempfile.gettempdir(),
            },
            clear=True,
        ):
            environment = candidate_environment(ROOT)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import shutil,tempfile; p=tempfile.mkdtemp(); "
                "print(tempfile.mkdtemp.__name__); shutil.rmtree(p)",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        expected = "_restricted_postgres_compatible_mkdtemp" if os.name == "nt" else "mkdtemp"
        self.assertEqual(result.stdout.strip(), expected)

    def test_postgresql_contract_uses_pg_ctl_restricted_server_launch(self) -> None:
        source = (TRUSTED_RUNTIME_SUPPORT / "sitecustomize.py").read_text(encoding="utf-8")
        self.assertIn('executable.with_name("pg_ctl.exe")', source)
        self.assertIn("class _PostgresCompatiblePopen(_original_popen)", source)
        self.assertIn("ctypes.windll.shell32.IsUserAnAdmin()", source)
        self.assertIn("subprocess.Popen = _PostgresCompatiblePopen", source)
        self.assertNotIn("PG_RESTRICT_EXEC", source)
        accepted = (ROOT / "trusted" / "accepted.py").read_text(encoding="utf-8")
        self.assertIn('environment["JUSTUS_TRUSTED_POSTGRES_PG_CTL"] = "1"', accepted)
        if os.name != "nt":
            return
        with patch.dict(
            os.environ,
            {
                "PHASE2_POSTGRES_BIN": str(ROOT),
                "SystemRoot": os.environ["SystemRoot"],
                "TEMP": tempfile.gettempdir(),
                "TMP": tempfile.gettempdir(),
            },
            clear=True,
        ):
            environment = candidate_environment(ROOT)
        environment["JUSTUS_TRUSTED_POSTGRES_PG_CTL"] = "1"
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import asyncio,json,sitecustomize; "
                "print(json.dumps(sitecustomize._postgres_launch_plan("
                "['C:/pg/bin/postgres.exe','-D','C:/data','-p','5433','-h','127.0.0.1'])[0]))",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(
            json.loads(result.stdout),
            [
                "C:\\pg\\bin\\pg_ctl.exe",
                "start",
                "-D",
                "C:\\data",
                "-o",
                "-p 5433 -h 127.0.0.1",
                "-w",
                "-s",
            ],
        )
        base = {"UNCHANGED": "yes", "JUSTUS_TRUSTED_POSTGRES_PG_CTL": "stale"}
        postgres = _contract_environment(base, "scripts/phase5_postgres_tests.py")
        ordinary = _contract_environment(base, "tests/test_budgeting.py")
        self.assertEqual(postgres["JUSTUS_TRUSTED_POSTGRES_PG_CTL"], "1")
        self.assertNotIn("JUSTUS_TRUSTED_POSTGRES_PG_CTL", ordinary)
        self.assertEqual(base["JUSTUS_TRUSTED_POSTGRES_PG_CTL"], "stale")

    def test_transport_reconstruction_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            relative = "fixture.json"
            expected = hashlib.sha256(b"a\r\nb\r\n").hexdigest()
            (root / relative).write_bytes(b"a\nb\n")
            with patch("trusted.common.CRLF_TRANSPORT_RECONSTRUCTION", {relative: expected}):
                restore_git_transport_bytes(root)
                self.assertEqual(hashlib.sha256((root / relative).read_bytes()).hexdigest(), expected)
                (root / relative).write_bytes(b"tampered\n")
                with self.assertRaises(TrustError):
                    restore_git_transport_bytes(root)

    def test_archive_verifier_rejects_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            archive_path = Path(name) / "bad.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("../escape.txt", b"bad")
            with self.assertRaises(TrustError):
                safe_archive_manifest(archive_path)


if __name__ == "__main__":
    unittest.main()





