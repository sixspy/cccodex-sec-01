def test_login_and_list(authed):
    me = authed.get("/api/me")
    assert me.status_code == 200
    assert me.json()["user"] == "admin"
    alerts = authed.get("/api/alerts")
    assert alerts.status_code == 200
    items = alerts.json()["items"]
    assert len(items) >= 3
    detail = authed.get(f"/api/alerts/{items[0]['id']}")
    assert detail.status_code == 200
    assert detail.json()["fingerprint"]


def test_unauthed_blocked(client):
    assert client.get("/api/alerts").status_code == 401


def test_login_page(client):
    r = client.get("/login")
    assert r.status_code == 200
    assert "安全事件分流台" in r.text
