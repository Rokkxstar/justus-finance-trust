"""Windows-only temp ACL compatibility for trusted candidate subprocesses."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence


if os.name == "nt":
    _original_mkdtemp = tempfile.mkdtemp
    _original_popen = subprocess.Popen

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

    def _postgres_launch_plan(arguments: Sequence[str]) -> tuple[list[str], Path]:
        values = [os.fspath(value) for value in arguments]
        executable = Path(values[0])
        try:
            data_index = values.index("-D", 1)
            data = Path(values[data_index + 1])
        except (ValueError, IndexError) as error:
            raise RuntimeError("trusted PostgreSQL launch requires a -D data directory") from error
        server_options = values[1:data_index] + values[data_index + 2 :]
        command = [
            str(executable.with_name("pg_ctl.exe")),
            "start",
            "-D",
            str(data),
            "-o",
            subprocess.list2cmdline(server_options),
            "-w",
            "-s",
        ]
        return command, data

    class _PgCtlManagedProcess:
        def __init__(self, arguments: Sequence[str], **kwargs: object) -> None:
            command, data = _postgres_launch_plan(arguments)
            if not Path(command[0]).is_file():
                raise RuntimeError(f"trusted PostgreSQL pg_ctl executable is missing: {command[0]}")
            self.args = list(arguments)
            self._data = data
            self._pg_ctl = command[0]
            self._cwd = kwargs.get("cwd")
            self._env = kwargs.get("env")
            self._creationflags = int(kwargs.get("creationflags", 0))
            self._stopped = False
            started = _original_popen(command, **kwargs)
            self.returncode = started.wait()
            self.pid = None

        def poll(self) -> int | None:
            if self.returncode != 0 or self._stopped:
                return self.returncode
            return None

        def _stop(self, mode: str) -> None:
            if self.poll() is not None:
                return
            stopped = _original_popen(
                [self._pg_ctl, "stop", "-D", str(self._data), "-m", mode, "-w", "-s"],
                cwd=self._cwd,
                env=self._env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.STDOUT,
                creationflags=self._creationflags,
            )
            code = stopped.wait(timeout=60)
            if code != 0:
                raise RuntimeError(f"trusted PostgreSQL pg_ctl stop failed with exit code {code}")
            self._stopped = True
            self.returncode = 0

        def terminate(self) -> None:
            self._stop("fast")

        def kill(self) -> None:
            self._stop("immediate")

        def wait(self, timeout: float | None = None) -> int:
            if self.poll() is None:
                raise subprocess.TimeoutExpired(self.args, timeout)
            return self.returncode

    class _PostgresCompatiblePopen(_original_popen):
        def __new__(cls, arguments: object, *args: object, **kwargs: object) -> object:
            if (
                os.environ.get("JUSTUS_TRUSTED_POSTGRES_PG_CTL") == "1"
                and not args
                and isinstance(arguments, (list, tuple))
                and arguments
                and Path(os.fspath(arguments[0])).name.lower() == "postgres.exe"
            ):
                return _PgCtlManagedProcess(arguments, **kwargs)
            return super().__new__(cls)

        def __init__(self, arguments: object, *args: object, **kwargs: object) -> None:
            super().__init__(arguments, *args, **kwargs)

    subprocess.Popen = _PostgresCompatiblePopen
