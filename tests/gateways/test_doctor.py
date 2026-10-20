"""Doctor describes actual composition without mistaking installation for verification."""
import json

from dea.contracts.adapter import UnimplementedAdapter
from dea.contracts.models import Backend
from dea.gateways.cli import main


def test_doctor_reports_live_composition(capsys):
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["adapters_implemented"] is True
    assert report["components"] == {
        "runtime": "dea.runtime.manager.AsyncProcessManager",
        "sessions": "dea.sessions.manager.SessionManager",
        "state": "dea.state.engine.StateEngine",
        "guard": "dea.contracts.wire.WireGuard",
    }
    assert set(report["adapters"]) == {"gdb", "lldb", "pdb"}
    for backend, adapter in report["adapters"].items():
        assert adapter["implemented"] is True
        assert adapter["implementation"].startswith(f"dea.adapters.{backend}.")
        assert adapter["capabilities"]["backend"] == backend
    assert report["capability_scope"] == "installation_eligibility"
    assert report["native_verification"] == "not_run"
    assert report["tokenizers"] == ["cl100k_base", "o200k_base"]


def test_missing_native_debuggers_do_not_mean_unimplemented(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DEA_GDB", str(tmp_path / "absent-gdb"))
    monkeypatch.setenv("DEA_LLDB_PYTHON", str(tmp_path / "absent-lldb-python"))
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["adapters_implemented"] is True
    assert report["adapters"]["gdb"]["capabilities"]["available"] is False
    assert report["adapters"]["lldb"]["capabilities"]["available"] is False
    assert report["adapters"]["pdb"]["capabilities"]["launch"] is True
    assert report["native_verification"] == "not_run"


def test_doctor_detects_a_placeholder_in_the_wired_registry(monkeypatch, capsys):
    import dea.bootstrap as bootstrap

    class Placeholder(UnimplementedAdapter):
        backend = Backend.PDB

    factories = dict(bootstrap.ADAPTER_FACTORIES)
    factories[Backend.PDB] = Placeholder
    monkeypatch.setattr(bootstrap, "ADAPTER_FACTORIES", factories)
    assert main(["doctor"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["adapters_implemented"] is False
    assert report["adapters"]["pdb"]["implemented"] is False
