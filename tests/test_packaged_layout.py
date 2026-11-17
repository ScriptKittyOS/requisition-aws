# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Sudo Apt Holdings LLC (Script Kitty OS & Labs)
"""The package works where a wheel installs it: requisition_aws/ alone in a site folder, with the files that
pyproject.toml's force-include maps into the wheel, and no bin/ beside it. The vendored ML-DSA verifier is the one
file the package reads from outside its own folder in this repository, so the wheel carries it inside the package
and pq.py loads it from there, under the same pinned SHA-256."""

import pathlib
import shutil
import subprocess
import sys
import tomllib

REPO = pathlib.Path(__file__).resolve().parent.parent


def _force_include():
    config = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    return config["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]


def _installed_layout(site):
    shutil.copytree(REPO / "requisition_aws", site / "requisition_aws",
                    ignore=shutil.ignore_patterns("__pycache__"))
    for source, target in _force_include().items():
        (site / target).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / source, site / target)


def _run(site, code):
    return subprocess.run([sys.executable, "-I", "-c", code, str(site)], capture_output=True, text=True)


def test_the_wheel_carries_the_vendored_verifier_and_its_licence_inside_the_package():
    assert _force_include() == {
        "bin/vendor/mldsa.py": "requisition_aws/_vendor/mldsa.py",
        "bin/vendor/LICENSE.mldsa": "requisition_aws/_vendor/LICENSE.mldsa",
    }


def test_pq_loads_the_vendored_verifier_from_the_installed_package(tmp_path):
    _installed_layout(tmp_path)
    proc = _run(tmp_path, "import sys; sys.path.insert(0, sys.argv[1]); from requisition_aws import pq; "
                          "pq.mldsa(); print(pq.MLDSA_PATH)")
    assert proc.returncode == 0, proc.stderr
    assert pathlib.Path(proc.stdout.strip()) == tmp_path / "requisition_aws" / "_vendor" / "mldsa.py"


def test_the_installed_copy_is_refused_when_its_bytes_change(tmp_path):
    _installed_layout(tmp_path)
    vendored = tmp_path / "requisition_aws" / "_vendor" / "mldsa.py"
    vendored.write_bytes(vendored.read_bytes() + b"\n# one more line\n")
    proc = _run(tmp_path, "import sys; sys.path.insert(0, sys.argv[1]); from requisition_aws import pq; pq.mldsa()")
    assert proc.returncode != 0 and "VendoredFileChanged" in proc.stderr, proc.stderr


def test_the_checkout_loads_the_one_copy_in_bin_vendor():
    from requisition_aws import pq
    assert pq.MLDSA_PATH == REPO / "bin" / "vendor" / "mldsa.py"
    assert not (REPO / "requisition_aws" / "_vendor").exists()
