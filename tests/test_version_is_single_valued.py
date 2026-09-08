"""The runtime version and the packaged version must be the same string.

`_SDK_VERSION` in client.py drives the User-Agent and the X-Arcezia-SDK header;
`pyproject.toml` drives what the wheel is called. Nothing tied them together, so
1.0.5 shipped from a tree whose client still introduced itself as 1.0.4 — the
release was mislabelled in every request it made. A comment asked for the two to
match. A comment is not a check.
"""
import pathlib
import re

import arcezia
from arcezia.client import _SDK_VERSION, _USER_AGENT

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _pyproject_version() -> str:
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"', text, re.M)
    assert match, "pyproject.toml has no top-level version"
    return match.group(1)


def test_runtime_version_matches_the_packaged_version():
    assert _SDK_VERSION == _pyproject_version()


def test_dunder_version_matches_too():
    assert arcezia.__version__ == _pyproject_version()


def test_user_agent_carries_that_same_version():
    assert _USER_AGENT == f"arcezia-python/{_pyproject_version()}"
