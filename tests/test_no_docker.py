"""Issue #17: the unit tests run without Docker - and fail loudly if one ever needs it."""
import os

import pytest


def test_unit_tests_cannot_reach_a_docker_daemon():
    if os.environ.get("NETMIND_INTEGRATION"):
        pytest.skip("integration run: the real daemon is wanted")
    import docker
    assert os.environ["DOCKER_HOST"].startswith("unix:///nonexistent/")
    with pytest.raises(Exception):
        docker.from_env().ping()
