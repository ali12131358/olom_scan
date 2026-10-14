from fastapi.testclient import TestClient
from backend.main import app
from backend import winbox_launcher

client = TestClient(app)

def test_winbox_launch_endpoint(monkeypatch):
    # Test when winbox is not found -> returns uri fallback
    monkeypatch.setattr(winbox_launcher, "find_winbox", lambda: None)
    res = client.post("/devices/launch-winbox", json={"ip": "172.18.1.12", "port": 8291})
    assert res.status_code == 200
    d = res.json()
    assert d["launched"] is False
    assert d["uri"] == "winbox://172.18.1.12"
    assert d["method"] == "uri"

def test_winbox_launch_with_mock_exe(monkeypatch):
    # Test when winbox is found and subprocess succeeds
    called = []
    def fake_popen(cmd, **kwargs):
        called.append(cmd)
        return None
    monkeypatch.setattr(winbox_launcher, "find_winbox", lambda: "C:\Program Files\Winbox\winbox64.exe")
    monkeypatch.setattr(winbox_launcher.subprocess, "Popen", fake_popen)

    res = client.post("/devices/launch-winbox", json={"ip": "192.168.88.1", "port": 8291})
    assert res.status_code == 200
    d = res.json()
    assert d["launched"] is True
    assert d["method"] == "exe"
    assert called == [["C:\Program Files\Winbox\winbox64.exe", "192.168.88.1:8291"]]

def test_winbox_protocol_redirect():
    res = client.get("/devices/winbox-protocol?ip=10.0.0.1&port=8291", follow_redirects=False)
    assert res.status_code in (307, 302, 303)
    assert res.headers["location"] == "winbox://10.0.0.1:8291"
