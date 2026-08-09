"""``arcbox.__version__`` resolution."""

from __future__ import annotations

import importlib
import importlib.metadata

import pytest

import arcbox


def test_version_is_exposed() -> None:
    # The install-smoke regression: the published package printed "n/a".
    assert arcbox.__version__
    assert arcbox.__version__ != "0.0.0.dev0"


def test_version_falls_back_when_no_distribution_is_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(name: str) -> str:
        raise importlib.metadata.PackageNotFoundError(name)

    try:
        with monkeypatch.context() as patch:
            patch.setattr(importlib.metadata, "version", missing)
            assert importlib.reload(arcbox).__version__ == "0.0.0.dev0"
    finally:
        # Re-resolve against the real metadata for later tests.
        importlib.reload(arcbox)
