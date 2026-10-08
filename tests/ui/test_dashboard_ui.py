"""Browser smoke test: the real web_server with a fake Docker layer, driven by headless Chromium.
Skipped automatically when Playwright or its browser is not installed."""
import socket
import threading
import time
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("playwright.sync_api")
import uvicorn  # noqa: E402
from playwright.sync_api import sync_playwright  # noqa: E402

import agent_core as core  # noqa: E402
import device_control as dc  # noqa: E402
import web_server as ws  # noqa: E402


class Box:
    def __init__(self, name):
        self.name, self.status = name, "running"

    def stop(self, timeout=10):
        time.sleep(0.4)
        self.status = "exited"

    def start(self):
        self.status = "running"

    def exec_run(self, cmd):
        return 0, (b"admin" if cmd[0] == "cat" else b"")


IDS = [("r1", "router", None), ("fw-branch1", "firewall", "branch1"), ("host-khalid", "host", "branch1"),
       ("host-khalil", "host", "branch1"), ("cam-khalid", "camera", "branch1")]


@pytest.fixture
def base_url(monkeypatch):
    registry = [{"id": i, "type": t, "owner": None if t in ("firewall", "router") else i.split("-")[1],
                 "container": f"c-{i}", "ip": f"10.0.0.{n + 2}", "segment": None, "branch": b}
                for n, (i, t, b) in enumerate(IDS)]
    boxes = {r["container"]: Box(r["container"]) for r in registry}
    monkeypatch.setattr(dc, "_load_registry", lambda: registry)
    monkeypatch.setattr(dc, "_client", NS(containers=NS(list=lambda all=False: list(boxes.values()), get=boxes.get)))
    monkeypatch.setattr(dc, "_reconnect_after_start", lambda _id: None)
    monkeypatch.setattr(dc, "_cached_audit", lambda fw: {"findings": ["Port 22 (SSH) is open"]})
    monkeypatch.setattr(ws, "ALERTS_PATH", None)
    audit = core.AuditLog()
    monkeypatch.setattr(ws, "AUDIT_LOG", audit)
    monkeypatch.setitem(ws.GUARDS, "simulated", core.Guard(ws.SIMULATED_DISPATCH, dc.find_devices, audit))
    for state in (ws.ALERT_LOG, ws._down_alert, ws._down_since, ws._finding_open, ws._last_sim_status):
        state.clear()
    dc._invalidate_dashboard_cache()

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(ws.app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        time.sleep(0.05)
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(5)


@pytest.fixture
def page(base_url):
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch()
        except Exception as e:  # browser binary not installed
            pytest.skip(f"Chromium unavailable: {e}")
        pg = browser.new_page(viewport={"width": 1500, "height": 900})
        pg.route("**/*", lambda r: r.continue_() if "127.0.0.1" in r.request.url else r.abort())  # no CDN needed
        pg.errors = []
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.goto(base_url)
        pg.wait_for_selector("#stat-devices:not(:text('--'))")
        yield pg
        browser.close()


def card_state(pg, device):
    return pg.inner_text(f'.device-card:has-text("{device}") .status').strip()


def test_power_off_shows_offline_without_flashing_online(page):
    page.click("#navDevices")
    assert card_state(page, "host-khalid") == "Online"
    page.click('.power-toggle[data-id="host-khalid"]')
    page.wait_for_selector("[data-testid=confirm-ok]")
    page.click("[data-testid=confirm-ok]")
    seen = []
    deadline = time.time() + 6
    while time.time() < deadline:
        seen.append(card_state(page, "host-khalid"))
        page.wait_for_timeout(40)
    after_first_offline = seen[seen.index("Offline"):]
    assert "Online" not in after_first_offline, f"status flickered: {seen}"
    assert page.errors == []


def test_alert_history_logs_and_report_after_an_outage(page):
    page.click("#navDevices")
    page.click('.power-toggle[data-id="host-khalil"]')
    page.click("[data-testid=confirm-ok]")
    page.wait_for_selector('.device-card:has-text("host-khalil") .status:text("Offline")')
    page.click('.power-toggle[data-id="host-khalil"]')
    page.wait_for_selector('.device-card:has-text("host-khalil") .status:text("Online")')

    page.click("#navAlerts")
    page.wait_for_selector("#all-alerts-list :text('Device Back Online')")
    text = page.inner_text("#all-alerts-list")
    assert "Device Offline" in text and "back online after" in text and "Camera Finding" in text

    page.click("#navLogs")
    page.wait_for_selector("#logs-tbody :text('Confirmed & executed')")
    assert "You (confirmation)" in page.inner_text("#logs-tbody")

    page.click("#navReports")
    page.wait_for_selector("#report-body :text('Open security findings')")
    assert "cam-khalid" in page.inner_text("#report-body")


def test_chat_clear_and_removed_widgets(page):
    for gone in ("#reset-demo", ".avatar", "#stat-traffic", "#devices-tbody"):
        assert page.locator(gone).count() == 0
    page.click("#navChat")
    page.evaluate("sessionStorage.setItem('netmind-chat', JSON.stringify({sid:'s',log:[{text:'hi',cls:'user',raw:false}]}))")
    page.reload()
    page.click("#navChat")
    assert "hi" in page.inner_text("#chat")
    page.click("#chat-clear")
    assert page.is_visible("#welcome")
    assert page.evaluate("sessionStorage.getItem('netmind-chat')") is None
