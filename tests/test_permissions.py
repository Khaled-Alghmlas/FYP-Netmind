"""Permissions: the server runs as a normal user and gets only what it needs.

Covers the sudo helper (scripts/netmind-reconnect) and how lab_network chooses between running as root,
the helper, and plain sudo. Nothing here needs root, Docker or a lab."""
import shutil
import subprocess
from pathlib import Path

import pytest

import lab_network as ln

ROOT = Path(__file__).resolve().parent.parent
HELPER_SCRIPT = ROOT / "scripts" / "netmind-reconnect"
SETUP_SCRIPT = ROOT / "scripts" / "setup-permissions.sh"
needs_bash = pytest.mark.skipif(shutil.which("bash") is None, reason="needs bash")

VETH = ["containerlab", "tools", "veth", "create", "-a", "clab-x:eth1", "-b", "bridge:br:p1", "--timeout", "20s"]


# --- how lab_network escalates ---------------------------------------------------------------
def test_root_runs_the_command_as_it_is(monkeypatch):
    monkeypatch.setattr(ln.os, "geteuid", lambda: 0)
    assert ln._as_root(VETH) == VETH


def test_a_normal_user_with_the_helper_installed_uses_only_the_helper(monkeypatch):
    monkeypatch.setattr(ln.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(ln.os, "access", lambda path, mode: path == ln.HELPER)
    assert ln._as_root(VETH) == ["sudo", "-n", ln.HELPER, "-a", "clab-x:eth1", "-b", "bridge:br:p1", "--timeout", "20s"]


def test_without_the_helper_it_falls_back_to_plain_sudo(monkeypatch):
    monkeypatch.setattr(ln.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(ln.os, "access", lambda path, mode: False)
    assert ln._as_root(VETH) == ["sudo", "-n"] + VETH


def test_the_helper_is_never_used_for_any_other_command(monkeypatch):
    monkeypatch.setattr(ln.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(ln.os, "access", lambda path, mode: True)
    other = ["containerlab", "destroy", "-t", "lab.yml"]
    assert ln._as_root(other) == ["sudo", "-n"] + other


# --- the helper refuses anything unexpected, before it does anything privileged ----------------
def run_helper(*args):
    return subprocess.run(["bash", str(HELPER_SCRIPT), *args], capture_output=True, text=True, timeout=30)


@needs_bash
def test_helper_check_succeeds():
    r = run_helper("--check")
    assert r.returncode == 0 and r.stdout.strip() == "ok"


@needs_bash
@pytest.mark.parametrize("args, message", [
    (["-a", "c;rm -rf /:eth1", "-b", "bridge:br:p1"], "invalid -a"),            # shell metacharacters
    (["-a", "-oProxy:eth1", "-b", "bridge:br:p1"], "invalid -a"),               # looks like an option
    (["-a", "clab-x:wlan0", "-b", "bridge:br:p1"], "invalid -a"),               # only ethN interfaces
    (["-a", "clab-x:eth1", "-b", "bridge:br;x:p1"], "invalid -b"),
    (["-a", "clab-x:eth1", "-b", "veth:br:p1"], "invalid -b"),                  # only bridge endpoints
    (["-a", "clab-x:eth1", "-b", "bridge:br:p1", "--timeout", "20"], "invalid --timeout"),
    (["-a", "clab-x:eth1", "-b", "bridge:br:p1", "--evil"], "unexpected argument"),
    (["-a"], "missing value"),
    ([], "invalid -a"),
])
def test_helper_rejects_bad_arguments(args, message):
    r = run_helper(*args)
    assert r.returncode == 2 and message in r.stderr


@needs_bash
def test_helper_refuses_a_container_that_containerlab_did_not_create():
    # well-formed arguments, but there is no such labelled container (the unit tests have no Docker)
    r = run_helper("-a", "not-a-lab-container:eth1", "-b", "bridge:br:p1")
    assert r.returncode == 2 and "not a containerlab container" in r.stderr


# --- the scripts themselves ------------------------------------------------------------------
@needs_bash
@pytest.mark.parametrize("script", [HELPER_SCRIPT, SETUP_SCRIPT])
def test_scripts_are_valid_bash(script):
    assert subprocess.run(["bash", "-n", str(script)], capture_output=True, timeout=30).returncode == 0


def test_the_sudo_rule_allows_the_helper_and_nothing_else():
    text = SETUP_SCRIPT.read_text()
    assert 'NOPASSWD: $HELPER"' in text and "NOPASSWD: ALL" not in text and "containerlab *" not in text
    assert "visudo -cf" in text                      # the rule is validated before it is installed
