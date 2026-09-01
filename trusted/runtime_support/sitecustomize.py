"""Windows-only temp ACL compatibility for trusted candidate subprocesses."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


if os.name == "nt":
    _original_mkdtemp = tempfile.mkdtemp

    def _restricted_postgres_compatible_mkdtemp(
        suffix: str | None = None,
        prefix: str | None = None,
        dir: str | os.PathLike[str] | None = None,
    ) -> str:
        name = _original_mkdtemp(suffix=suffix, prefix=prefix, dir=dir)
        root = Path(name)
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
            shutil.rmtree(root, ignore_errors=True)
            raise RuntimeError(
                f"could not make temporary directory usable by restricted PostgreSQL: {result.stdout}"
            )
        return name

    tempfile.mkdtemp = _restricted_postgres_compatible_mkdtemp
