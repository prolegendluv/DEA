"""Bounded, shell-free discovery of a Python interpreter that can load LLDB."""
from __future__ import annotations

from dataclasses import dataclass
import json
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys

HELPER = Path(__file__).with_name("helper.py")


@dataclass(frozen=True)
class Interpreter:
    executable: str
    module_path: str | None = None


def candidate() -> Interpreter | None:
    """Fast installation eligibility check; ABI verification occurs before spawn.

    No subprocesses or native LLDB imports are allowed in adapter construction.
    """
    explicit = os.environ.get("DEA_LLDB_PYTHON")
    module_path = os.environ.get("DEA_LLDB_MODULE_PATH")
    if explicit:
        executable = shutil.which(explicit)
        return Interpreter(executable, module_path) if executable else None
    if module_path:
        path = Path(module_path)
        return Interpreter(sys.executable, module_path) if (path / "lldb").is_dir() else None
    try:
        if importlib.util.find_spec("lldb") is not None:
            return Interpreter(sys.executable)
    except (ImportError, ValueError):
        pass
    # lldb -P is intentionally deferred until asynchronous probing.
    if shutil.which("lldb"):
        return Interpreter(sys.executable)
    return None


def discover() -> Interpreter | None:
    """Probe native API initialization, including ABI loading, in an isolated process.

    DEA_LLDB_PYTHON and DEA_LLDB_MODULE_PATH select a vendor-provided installation.
    An explicit interpreter is authoritative; never silently switch ABIs after failure.
    """
    explicit = os.environ.get("DEA_LLDB_PYTHON")
    module_path = os.environ.get("DEA_LLDB_MODULE_PATH")
    if module_path and not Path(module_path).is_dir():
        return None
    if not module_path and (lldb := shutil.which("lldb")):
        try:
            result = subprocess.run([lldb, "-P"], capture_output=True, text=True,
                                    timeout=3, check=False,
                                    creationflags=0x08000000 if os.name == "nt" else 0)
            candidate = result.stdout.strip()
            if result.returncode == 0 and Path(candidate).is_dir():
                module_path = candidate
        except (OSError, subprocess.SubprocessError):
            pass
    candidates = [explicit] if explicit else [sys.executable, shutil.which("python3"), shutil.which("python")]
    seen = set()
    for executable in candidates:
        if not executable or executable in seen:
            continue
        seen.add(executable)
        command = [executable, "-I", str(HELPER), "--probe"]
        if module_path:
            command.extend(["--module-path", module_path])
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=3,
                                    check=False, creationflags=0x08000000 if os.name == "nt" else 0)
            if result.returncode == 0 and json.loads(result.stdout) == {"available": True}:
                return Interpreter(executable, module_path)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
    return None
