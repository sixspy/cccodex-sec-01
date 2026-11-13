"""七段核对：同指纹分流规矩、走法拦截、争抢、空级别、策略锁定、待复核、台面识别。"""
import os

import pytest
from fastapi.testclient import TestClient

from app.db import init_db
from app.main import app


def _make_client(tmp_path):
    db = tmp_path / "test.db"
    os.environ["DATABASE_PATH"] = str(db)
    init_db(str(db))
    c = TestClient(app)
    r = c.post("/api/login", json={"username": "admin", "password": "123456"})
    assert r.status_code == 200
    return c


def _pick_fp(client, fp):
    items = client.get("/api/alerts").json()["items"]
    return [a for a in items if a["fingerprint"] == fp]


def _set_policy(client, rule):
    r = client.post("/api/policy", json={"rule": rule, "note": "当日值班"})
    assert r.status_code == 200, r.text
    return r.json()["policy"]


def _claim(client, alert_id, operator):
    return client.post(
        f"/api/alerts/{alert_id}/claim", json={"operator": operator}
    )


# ---------- 第一段：同指纹按所选规矩合并或串联 ----------

def test_segment_1_same_fingerprint_merge_or_chain(tmp_path):
    # 规矩 A：merge —— 同指纹收成一张处置单
    client = _make_client(tmp_path / "a")
    _set_policy(client, "merge")
    fp_alerts = _pick_fp(client, "auth.bruteforce")
    assert len(fp_alerts) >= 2
    r1 = _claim(client, fp_alerts[0]["id"], "alice")
    r2 = _claim(client, fp_alerts[1]["id"], "bob")
    assert r1.status_code == 200 and r2.status_code == 200
    tid1, tid2 = r1.json()["ticket"]["id"], r2.json()["ticket"]["id"]
    assert tid1 == tid2, "merge 规矩下同指纹必须收成同一单"
    ticket = client.get(f"/api/tickets/{tid1}").json()
    assert ticket["mode"] == "merge"
    assert len(ticket["alerts"]) == 2

    # 规矩 B：chain —— 各自留单并以链条互指
    client2 = _make_client(tmp_path / "b")
    _set_policy(client2, "chain")
    fp_alerts = _pick_fp(client2, "auth.bruteforce")
    r1 = _claim(client2, fp_alerts[0]["id"], "alice")
    r2 = _claim(client2, fp_alerts[1]["id"], "bob")
    t1, t2 = r1.json()["ticket"], r2.json()["ticket"]
    assert t1["id"] != t2["id"], "chain 规矩下必须各自留单"
    assert t1["chain_id"] == t2["chain_id"], "两张单必须挂同一条链"
    # 链条关系以最新详情为准
    t1_fresh = client2.get(f"/api/tickets/{t1['id']}").json()
    t2_fresh = client2.get(f"/api/tickets/{t2['id']}").json()
    assert t1_fresh["chain"]["next_id"] == t2["id"]
    assert t2_fresh["chain"]["prev_id"] == t1["id"]
    assert [p["id"] for p in t2_fresh["chain"]["peers"]] == [t1["id"], t2["id"]]


# ---------- 第二段：走法不符会被服务端拦下 ----------

def test_segment_2_submit_mode_mismatch_rejected(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    fp_alerts = _pick_fp(client, "auth.bruteforce")
    ticket = _claim(client, fp_alerts[0]["id"], "alice").json()["ticket"]

    # 当日策略是 merge，却按 chain 收口 -> 拦下并提示走法不符
    bad = client.post(
        f"/api/tickets/{ticket['id']}/submit",
        json={"mode": "chain", "conclusion": "硬走串联"},
    )
    assert bad.status_code == 400
    assert "走法不符" in bad.json()["detail"]

    # 按策略走法提交才放行
    ok = client.post(
        f"/api/tickets/{ticket['id']}/submit",
        json={"mode": "merge", "conclusion": "合并收口"},
    )
    assert ok.status_code == 200
    assert ok.json()["ticket"]["status"] == "已结案"


# ---------- 第三段：双人争抢同一条只成一笔，另一笔记争抢失败 ----------

def test_segment_3_contention_only_one_wins(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    target = _pick_fp(client, "runtime.escape")[0]

    first = _claim(client, target["id"], "alice")
    second = _claim(client, target["id"], "bob")
    assert first.status_code == 200
    assert second.status_code == 409
    assert "争抢失败" in second.json()["detail"]

    detail = client.get(f"/api/alerts/{target['id']}").json()
    results = [h["result"] for h in detail["claim_history"]]
    assert results.count("success") == 1
    assert results.count("failed") == 1

    board = client.get("/api/board").json()
    assert any(c["operator"] == "bob" for c in board["contentions"])


def test_segment_3b_claim_requires_operator_name(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    target = _pick_fp(client, "runtime.escape")[0]
    r = client.post(f"/api/alerts/{target['id']}/claim", json={"operator": "  "})
    assert r.status_code == 400
    assert "操作员" in r.json()["detail"]


# ---------- 第四段：级别空着的告警不许合并、不许认领 ----------

def test_segment_4_empty_severity_cannot_claim(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    empty = [a for a in client.get("/api/alerts").json()["items"]
             if a["fingerprint"] == "net.exfil"][0]
    assert empty["severity"] == ""
    assert empty["claimable"] is False

    r = _claim(client, empty["id"], "alice")
    assert r.status_code == 400
    assert "级别空缺" in r.json()["detail"]

    # 同指纹再来一条有级别的，空级别那条依旧不能被认领
    client.post("/api/alerts", json={
        "title": "异常外联探测·补指纹",
        "fingerprint": "net.exfil",
        "severity": "高",
    })
    r2 = _claim(client, empty["id"], "alice")
    assert r2.status_code == 400


# ---------- 第五段：处置没收口时，策略说明禁止改动；当天不许换 ----------

def test_segment_5_policy_locked_while_open(tmp_path):
    client = _make_client(tmp_path)
    policy = _set_policy(client, "merge")
    assert "同指纹收成一单" in policy["statement"]

    # 当天不许换规矩
    again = client.post("/api/policy", json={"rule": "chain"})
    assert again.status_code == 400
    assert "当天不许换" in again.json()["detail"]

    # 有未收口处置单时，策略说明禁止改动
    target = _pick_fp(client, "runtime.escape")[0]
    _claim(client, target["id"], "alice")
    locked = client.post("/api/policy", json={"rule": "merge", "note": "想改说明"})
    assert locked.status_code == 400
    assert "收口" in locked.json()["detail"]

    # 收口后当天仍然不许换规矩
    tickets = client.get("/api/tickets").json()["items"]
    client.post(
        f"/api/tickets/{tickets[0]['id']}/submit",
        json={"mode": "merge", "conclusion": "收口"},
    )
    still = client.post("/api/policy", json={"rule": "chain"})
    assert still.status_code == 400
    assert "当天不许换" in still.json()["detail"]


# ---------- 第六段：结案后同指纹新告警涌进，卡片回到待复核 ----------

def test_segment_6_reopen_to_review_on_new_same_fingerprint(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    target = _pick_fp(client, "tls.expiry")[0]
    ticket = _claim(client, target["id"], "alice").json()["ticket"]
    client.post(
        f"/api/tickets/{ticket['id']}/submit",
        json={"mode": "merge", "conclusion": "收口"},
    )
    assert client.get(f"/api/tickets/{ticket['id']}").json()["status"] == "已结案"

    # 同指纹新告警进台
    new = client.post("/api/alerts", json={
        "title": "证书即将过期·再次触发",
        "fingerprint": "tls.expiry",
        "severity": "中",
    }).json()["item"]
    assert new["status"] == "待认领"

    reopened = client.get(f"/api/tickets/{ticket['id']}").json()
    assert reopened["status"] == "待复核", "旧结案不得继续充当完成"
    assert reopened["closed_at"] is None
    member_status = {a["id"]: a["status"] for a in reopened["alerts"]}
    assert all(s == "待复核" for s in member_status.values())

    # 新告警按当日规矩并入这张待复核单
    again = _claim(client, new["id"], "alice")
    assert again.status_code == 200
    assert again.json()["ticket"]["id"] == ticket["id"]

    board = client.get("/api/board").json()
    assert board["counts"]["review"] == 1
    assert board["counts"]["closed"] == 0


def test_segment_6b_chain_reopen_each_ticket_to_review(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "chain")
    fp_alerts = _pick_fp(client, "policy.drift")
    t1 = _claim(client, fp_alerts[0]["id"], "alice").json()["ticket"]
    for t in (t1,):
        r = client.post(
            f"/api/tickets/{t['id']}/submit",
            json={"mode": "chain", "conclusion": "收口"},
        )
        assert r.status_code == 200
    client.post("/api/alerts", json={
        "title": "策略配置漂移·再来",
        "fingerprint": "policy.drift",
        "severity": "中",
    })
    assert client.get(f"/api/tickets/{t1['id']}").json()["status"] == "待复核"


# ---------- 第七段：台面一眼认出策略名、待认领、争抢落败 ----------

def test_segment_7_board_recognition(tmp_path):
    client = _make_client(tmp_path)
    _set_policy(client, "merge")
    target = _pick_fp(client, "runtime.escape")[0]
    _claim(client, target["id"], "alice")
    _claim(client, target["id"], "bob")  # 争抢失败

    board = client.get("/api/board").json()
    assert board["policy"]["rule_name"] == "同指纹收成一单"
    assert set(board["counts"]) >= {"pending", "handling", "review", "closed"}
    assert board["counts"]["handling"] >= 1
    assert board["contentions"], "台面必须露出争抢落败"
    assert all(c["operator"] for c in board["contentions"])

    # 静态页面：候审区标题固定“待认领”，策略名与争抢落败文案可识别
    page = client.get("/app/").text
    assert "安全事件分流台" in page
    js = client.get("/static/js/app.js").text
    assert "待认领" in js
    assert "争抢落败" in js
    assert "同指纹收成一单" in js and "分单再串联" in js
