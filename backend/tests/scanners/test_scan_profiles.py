"""QUICK and FULL Nmap command variants, timeouts and privilege fallback."""

import uuid
from unittest.mock import MagicMock, patch

import pytest

from app.core.config import Settings
from app.core.enums import ScanProfile
from app.scanners.adapters.nmap_adapter import FULL_SCRIPT_SELECTION, NmapAdapter
from app.scanners.scan_artifact import ScanArtifact


def _cmd(profile: ScanProfile, privileged: bool) -> list[str]:
    with patch(
        "app.scanners.adapters.nmap_adapter._needs_privileged_flag", return_value=False
    ):
        return NmapAdapter().build_command(
            "10.0.0.5", profile, "out.xml", force_privileged=privileged
        )


def _value_after(cmd: list[str], flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_quick_privileged_uses_syn_scan_os_detection_and_top_ports():
    cmd = _cmd(ScanProfile.QUICK, privileged=True)
    assert "-sS" in cmd
    assert "-O" in cmd
    assert "--osscan-limit" in cmd
    assert _value_after(cmd, "--top-ports") == "1000"
    assert _value_after(cmd, "--host-timeout") == "10m"
    assert "-p-" not in cmd
    assert "--script" not in cmd


def test_full_privileged_scans_all_ports_with_safe_scripts_and_traceroute():
    cmd = _cmd(ScanProfile.FULL, privileged=True)
    assert "-sS" in cmd
    assert "-O" in cmd
    assert "--traceroute" in cmd
    assert "-p-" in cmd
    assert _value_after(cmd, "--script") == FULL_SCRIPT_SELECTION
    assert _value_after(cmd, "--host-timeout") == "90m"


@pytest.mark.parametrize("profile", [ScanProfile.QUICK, ScanProfile.FULL])
def test_unprivileged_variants_use_connect_scan_without_os_detection(profile):
    cmd = _cmd(profile, privileged=False)
    assert "-sT" in cmd
    assert "-sS" not in cmd
    assert "-O" not in cmd
    assert "--traceroute" not in cmd


def test_full_scripts_stay_safe_and_on_target():
    assert "and safe" in FULL_SCRIPT_SELECTION
    assert "not (broadcast or external)" in FULL_SCRIPT_SELECTION
    for intrusive in ("intrusive", "dos", "exploit", "brute"):
        assert intrusive not in FULL_SCRIPT_SELECTION


@pytest.mark.parametrize("profile", [ScanProfile.QUICK, ScanProfile.FULL])
def test_target_is_always_last_and_output_is_xml(profile):
    cmd = _cmd(profile, privileged=True)
    assert cmd[-1] == "10.0.0.5"
    assert _value_after(cmd, "-oX") == "out.xml"


@pytest.mark.parametrize(
    ("profile", "expected"), [(ScanProfile.QUICK, 900), (ScanProfile.FULL, 6300)]
)
def test_outer_timeout_follows_the_profile(profile, expected):
    executor = MagicMock()
    executor.run_scanner.return_value = MagicMock(spec=ScanArtifact, exit_code=0)
    with patch(
        "app.scanners.adapters.nmap_adapter.detect_privileged_mode", return_value=False
    ):
        adapter = NmapAdapter(executor=executor)
        # Defaults only: a developer's .env may override SCAN_TIMEOUT.
        adapter.settings = Settings(_env_file=None)
        adapter.execute(uuid.uuid4(), "10.0.0.5", profile)
    assert executor.run_scanner.call_args.kwargs["timeout"] == expected


def test_quick_retries_unprivileged_after_a_privilege_error():
    failed = MagicMock(
        spec=ScanArtifact, exit_code=1, stderr="requires root privileges"
    )
    ok = MagicMock(spec=ScanArtifact, exit_code=0, stderr="")
    executor = MagicMock()
    executor.run_scanner.side_effect = [failed, ok]
    with (
        patch(
            "app.scanners.adapters.nmap_adapter.detect_privileged_mode",
            return_value=True,
        ),
        patch(
            "app.scanners.adapters.nmap_adapter._needs_privileged_flag",
            return_value=False,
        ),
    ):
        result = NmapAdapter(executor=executor).execute(
            uuid.uuid4(), "10.0.0.5", ScanProfile.QUICK
        )
    assert result is ok
    retry_cmd = executor.run_scanner.call_args_list[1].kwargs["cmd_args"]
    assert "-sT" in retry_cmd
