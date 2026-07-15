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
from bundleInspector.collector.scope import ScopePolicy
from bundleInspector.config import CrawlerConfig, ScopeConfig


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


@pytest.mark.asyncio
async def test_context_creation_failure_closes_lazy_security_proxy(monkeypatch):
    closed = {"value": False}

    class _Proxy:
        url = "socks5://127.0.0.1:43210"

        def __init__(self, **kwargs):
            self.started = False

        async def start(self):
            self.started = True

        async def close(self):
            closed["value"] = True

    class _Browser:
        async def new_context(self, **kwargs):
            raise RuntimeError("context failed")

    monkeypatch.setattr(headless_mod, "PLAYWRIGHT_AVAILABLE", True)
    monkeypatch.setattr(headless_mod, "ValidatingSocksProxy", _Proxy)
    collector = HeadlessCollector(CrawlerConfig())
    collector._browser = _Browser()

    with pytest.raises(RuntimeError, match="context failed"):
        await collector._create_context(
            "https://example.com/app",
            ScopePolicy(ScopeConfig()),
        )

    assert closed["value"] is True
    assert collector._socks_proxy is None


@pytest.mark.asyncio
async def test_teardown_closes_proxy_and_driver_when_browser_close_raises(monkeypatch):
    events: list[str] = []

    class _Browser:
        async def close(self):
            events.append("browser")
            raise RuntimeError("browser crashed")

    class _Proxy:
        async def close(self):
            events.append("proxy")

    class _Playwright:
        async def stop(self):
            events.append("playwright")

    monkeypatch.setattr(headless_mod, "PLAYWRIGHT_AVAILABLE", True)
    collector = HeadlessCollector(CrawlerConfig())
    collector._browser = _Browser()
    collector._socks_proxy = _Proxy()
    collector._playwright = _Playwright()

    with pytest.raises(RuntimeError, match="browser crashed"):
        await collector.teardown()

    assert events == ["browser", "proxy", "playwright"]
    assert collector._browser is None
    assert collector._playwright is None
    assert collector._socks_proxy is None


@pytest.mark.asyncio
async def test_teardown_clears_references_when_driver_stop_raises(monkeypatch):
    events: list[str] = []

    class _Browser:
        async def close(self):
            events.append("browser")

    class _Proxy:
        async def close(self):
            events.append("proxy")

    class _Playwright:
        async def stop(self):
            events.append("playwright")
            raise RuntimeError("driver shutdown failed")

    monkeypatch.setattr(headless_mod, "PLAYWRIGHT_AVAILABLE", True)
    collector = HeadlessCollector(CrawlerConfig())
    collector._browser = _Browser()
    collector._socks_proxy = _Proxy()
    collector._playwright = _Playwright()

    with pytest.raises(RuntimeError, match="driver shutdown failed"):
        await collector.teardown()

    assert events == ["browser", "proxy", "playwright"]
    assert collector._browser is None
    assert collector._playwright is None
    assert collector._socks_proxy is None


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
