"""Regression tests for the headless browser-lifecycle + Windows shutdown-noise fixes.

Reproduces the reported failure: with the browser not installed, setup() raised from
__aenter__ so __aexit__/teardown never ran, orphaning the Playwright Node driver
subprocess -> Windows Proactor loop printed 'I/O operation on closed pipe' from transport
__del__ at interpreter shutdown.
"""

from __future__ import annotations

import sys

import pytest

import bundleInspector.collector.headless as headless_mod
from bundleInspector.collector.headless import HeadlessCollector
from bundleInspector.config import CrawlerConfig


@pytest.mark.asyncio
async def test_setup_stops_driver_when_launch_fails(monkeypatch):
    """If chromium.launch() fails (browser not installed), setup() must stop the driver it
    just started (so the subprocess/pipes close in-loop) and re-raise -- otherwise the
    driver leaks because __aenter__ failing means teardown() never runs."""
    stopped = {"v": False}

    class _Chromium:
        async def launch(self, **kwargs):
            raise RuntimeError("BrowserType.launch: Executable doesn't exist at ...")

    class _PW:
        chromium = _Chromium()

        async def stop(self):
            stopped["v"] = True

    class _Starter:
        async def start(self):
            return _PW()

    monkeypatch.setattr(headless_mod, "async_playwright", lambda: _Starter())

    collector = HeadlessCollector(CrawlerConfig())
    with pytest.raises(RuntimeError, match="Executable doesn't exist"):
        await collector.setup()
    assert stopped["v"] is True            # driver stopped on the failure path
    assert collector._playwright is None    # and reference cleared


@pytest.mark.skipif(sys.platform != "win32", reason="Proactor transports are Windows-only")
def test_silence_proactor_shutdown_noise_is_idempotent():
    from asyncio.base_subprocess import BaseSubprocessTransport
    from asyncio.proactor_events import _ProactorBasePipeTransport

    from bundleInspector.cli import _silence_proactor_shutdown_noise

    _silence_proactor_shutdown_noise()
    assert getattr(_ProactorBasePipeTransport.__del__, "_bi_silenced", False)
    assert getattr(BaseSubprocessTransport.__del__, "_bi_silenced", False)

    # Calling again must not double-wrap.
    del1 = _ProactorBasePipeTransport.__del__
    del2 = BaseSubprocessTransport.__del__
    _silence_proactor_shutdown_noise()
    assert _ProactorBasePipeTransport.__del__ is del1
    assert BaseSubprocessTransport.__del__ is del2
