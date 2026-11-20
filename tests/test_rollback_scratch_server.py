# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The rollback demo's scratch server: the demo holds no command for it (the operator gives the one Requisition's
scratch-server script states, which never compiles); stop() returns only once the scratch server's port is closed
and its process group is gone, with a bounded wait and a loud failure."""

import socket
import sys
import textwrap
import time

import pytest

from requisition_aws.demo_flow import Transcript

from .test_rollback_guards import _free_port, scratch_env  # noqa: F401  (scratch_env is a fixture)
from .test_rollback_demo import demo


def test_d1_no_server_command_is_built_in(scratch_env, tmp_path):
    assert not hasattr(demo, "DEFAULT_SERVER_CMD")
    with pytest.raises(demo.Refused, match="name the command that starts Requisition's scratch server"):
        demo.ScratchLab(source_db="demo_source", port=_free_port(), server_cmd="", out_dir=tmp_path, t=Transcript())


def _port_open(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


def _wrapper_and_slow_server(port, tmp_path):
    """Like a load wrapper -> the BEAM: a wrapper that dies on SIGTERM at once, and a child in the same process
    group that holds the port and takes ~2 s to shut down after SIGTERM."""
    child = tmp_path / "child.py"
    child.write_text(textwrap.dedent(f"""
        import signal, socket, sys, time
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", {port})); s.listen()
        def slow(*_):
            time.sleep(2); s.close(); sys.exit(0)
        signal.signal(signal.SIGTERM, slow)
        print("ROLLBACK SCRATCH SERVER UP on 127.0.0.1:{port}, database scratch_20261110120000_1_2, job queues off, pid 1", flush=True)
        while True:
            time.sleep(0.1)
    """))
    wrapper = tmp_path / "wrapper.py"
    wrapper.write_text(textwrap.dedent(f"""
        import subprocess, sys, time
        subprocess.Popen([{sys.executable!r}, {str(child)!r}])
        while True:
            time.sleep(0.1)
    """))
    return f"{sys.executable} {wrapper}"


def test_d2_stop_returns_only_once_the_port_is_closed(scratch_env, tmp_path):
    port = _free_port()
    lab = demo.ScratchLab(source_db="demo_source", port=port,
                          server_cmd=_wrapper_and_slow_server(port, tmp_path), out_dir=tmp_path, t=Transcript(),
                          start_timeout=20)
    lab.start()
    deadline = time.monotonic() + 10
    while not _port_open(port) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert _port_open(port)
    lab.stop()
    assert not _port_open(port)  # the slow child closed it before stop() returned
    assert lab.proc is None


def test_d2_a_port_still_open_after_the_bounded_wait_is_a_loud_failure(scratch_env, tmp_path):
    port = _free_port()
    up = f"ROLLBACK SCRATCH SERVER UP on 127.0.0.1:{port}, database scratch_20261110120000_1_2, job queues off, pid 1"
    lab = demo.ScratchLab(source_db="demo_source", port=port,
                          server_cmd=f"{sys.executable} -c \"print({up!r}, flush=True); import time; time.sleep(30)\"",
                          out_dir=tmp_path, t=Transcript(), start_timeout=20, stop_timeout=1)
    lab.start()
    with socket.socket() as stranger:  # something outside the server's process group holds the port
        stranger.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        stranger.bind(("127.0.0.1", port))
        stranger.listen()
        with pytest.raises(RuntimeError, match="still"):
            lab.stop()
