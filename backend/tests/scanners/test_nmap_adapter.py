import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from app.core.enums import ScannerType, ScanProfile
from app.core.exceptions import ScannerExecutionException
from app.scanners.adapters.nmap_adapter import FULL_SCRIPT_SELECTION, NmapAdapter
from app.scanners.scan_artifact import ScanArtifact


def test_nmap_adapter_get_scanner_type():
    adapter = NmapAdapter()
    assert adapter.get_scanner_type() == ScannerType.NMAP


def test_nmap_adapter_build_command():
    adapter = NmapAdapter()

    # Quick profile (unprivileged variant)
    cmd = adapter.build_command(
        "192.168.1.1", ScanProfile.QUICK, "out.xml", force_privileged=False
    )
    assert "-sT" in cmd
    assert cmd[cmd.index("--top-ports") + 1] == "1000"
    assert "--version-light" in cmd
    assert "-oX" in cmd
    assert "out.xml" in cmd
    assert cmd[-1] == "192.168.1.1"

    # Full profile
    cmd = adapter.build_command("example.com", ScanProfile.FULL, "out.xml")
    assert "-sV" in cmd
    assert cmd[cmd.index("--script") + 1] == FULL_SCRIPT_SELECTION
    assert "-p-" in cmd
    assert "-Pn" in cmd
    assert "--host-timeout" in cmd
    assert "90m" in cmd
    assert "-oX" in cmd
    assert "out.xml" in cmd
    assert cmd[-1] == "example.com"


def test_nmap_adapter_build_command_sanitization():
    adapter = NmapAdapter()

    # Reject option injection in target
    with pytest.raises(ScannerExecutionException) as exc:
        adapter.build_command("-sS", ScanProfile.QUICK, "out.xml")
    assert "cannot start with a hyphen" in str(exc.value)


def test_nmap_adapter_execute():
    # Mock Executor
    mock_executor = MagicMock()
    mock_artifact = MagicMock(spec=ScanArtifact)
    mock_executor.run_scanner.return_value = mock_artifact

    adapter = NmapAdapter(executor=mock_executor)
    scan_id = uuid.uuid4()

    result = adapter.execute(scan_id, "192.168.1.1", ScanProfile.QUICK)

    assert result is mock_artifact
    mock_executor.run_scanner.assert_called_once()

    # Assert output directory contains the XML filename
    call_args = mock_executor.run_scanner.call_args[1]
    assert call_args["scanner_type"] == ScannerType.NMAP
    assert call_args["scan_id"] == scan_id
    assert isinstance(call_args["output_path"], Path)
    assert call_args["output_path"].name == f"nmap_{scan_id}.xml"
