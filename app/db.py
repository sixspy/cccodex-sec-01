import sqlite3
from contextlib import contextmanager
from datetime import date as date_cls
from pathlib import Path

from app.config import Config

# 当日策略的两种唯一规矩
RULES = {
    "merge": "同指纹收成一单",
    "chain": "分单再串联",
}

TICKET_HANDLING = "处置中"
TICKET_REVIEW = "待复核"
TICKET_CLOSED = "已结案"
OPEN_TICKET_STATES = (TICKET_HANDLING, TICKET_REVIEW)

ALERT_PENDING = "待认领"
ALERT_HANDLING = "处置中"
ALERT_REVIEW = "待复核"
ALERT_CLOSED = "已结案"

SEED_ALERTS = [
    ("主机异常登录", "auth.bruteforce", "高"),
    ("主机异常登录·重复指纹", "auth.bruteforce", "高"),
    ("容器逃逸嫌疑", "runtime.escape", "高"),
    ("证书即将过期", "tls.expiry", "中"),
    ("异常外联探测", "net.exfil", ""),           # 级别空缺：禁止认领、禁止合并
    ("策略配置漂移", "policy.drift", "中"),
]


class DomainError(Exception):
    """业务规则违规，由路由层翻译成 HTTP 错误。"""

    def __init__(self, status_code: int, message: str):
        super().__init__(message)
        self.status_code = status_code
        self.message = message


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or Config.database()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    # autocommit 模式，服务函数内用 BEGIN IMMEDIATE 显式开事务，保证并发认领串行化
    conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db(db_path: str | None = None):
    conn = connect(db_path)
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(db_path: str | None = None) -> None:
    with get_db(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS alerts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              title TEXT NOT NULL,
              fingerprint TEXT NOT NULL,
              severity TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT '待认领',
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS policies (
              policy_date TEXT PRIMARY KEY,
              rule TEXT NOT NULL,
              rule_name TEXT NOT NULL,
              statement TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS tickets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              fingerprint TEXT NOT NULL,
              mode TEXT NOT NULL,
              status TEXT NOT NULL,
              owner TEXT NOT NULL,
              chain_id TEXT,
              chain_seq INTEGER,
              conclusion TEXT,
              created_at TEXT NOT NULL DEFAULT (datetime('now')),
              closed_at TEXT
            );
            CREATE TABLE IF NOT EXISTS ticket_alerts (
              ticket_id INTEGER NOT NULL REFERENCES tickets(id),
              alert_id INTEGER PRIMARY KEY REFERENCES alerts(id),
              joined_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS claim_attempts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              alert_id INTEGER NOT NULL REFERENCES alerts(id),
              operator TEXT NOT NULL,
              result TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        # 兼容基线库的旧状态文案
        conn.execute(
            "UPDATE alerts SET status = ? WHERE status = '待分流'", (ALERT_PENDING,)
        )
        n = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        if n == 0:
            conn.executemany(
                "INSERT INTO alerts (title, fingerprint, severity, status) "
                "VALUES (?,?,?,?)",
                [(t, fp, sev, ALERT_PENDING) for t, fp, sev in SEED_ALERTS],
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('lab_name', ?)",
                ("安全事件分流台",),
            )


def today_str() -> str:
    return date_cls.today().isoformat()


# ---------- 序列化 ----------

def _failed_claims(conn: sqlite3.Connection, alert_ids: list[int]) -> list[dict]:
    if not alert_ids:
        return []
    placeholders = ",".join("?" * len(alert_ids))
    rows = conn.execute(
        f"SELECT alert_id, operator, created_at FROM claim_attempts "
        f"WHERE result = 'failed' AND alert_id IN ({placeholders}) ORDER BY id",
        alert_ids,
    ).fetchall()
    return [dict(r) for r in rows]


def _alert_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    ta = conn.execute(
        "SELECT ticket_id FROM ticket_alerts WHERE alert_id = ?", (row["id"],)
    ).fetchone()
    d["ticket_id"] = ta["ticket_id"] if ta else None
    d["failed_claims"] = _failed_claims(conn, [row["id"]])
    d["claimable"] = bool(row["severity"]) and d["ticket_id"] is None
    return d


def _ticket_dict(conn: sqlite3.Connection, row: sqlite3.Row) -> dict:
    d = dict(row)
    d["mode_name"] = RULES.get(row["mode"], row["mode"])
    members = conn.execute(
        "SELECT a.* FROM ticket_alerts ta JOIN alerts a ON a.id = ta.alert_id "
        "WHERE ta.ticket_id = ? ORDER BY a.id",
        (row["id"],),
    ).fetchall()
    d["alerts"] = [_alert_dict(conn, m) for m in members]
    d["failed_claims"] = _failed_claims(conn, [m["id"] for m in members])

    d["chain"] = None
    if row["mode"] == "chain" and row["chain_id"]:
        peers = conn.execute(
            "SELECT id, status, owner, chain_seq FROM tickets "
            "WHERE chain_id = ? ORDER BY chain_seq, id",
            (row["chain_id"],),
        ).fetchall()
        peer_ids = [p["id"] for p in peers]
        idx = peer_ids.index(row["id"])
        d["chain"] = {
            "chain_id": row["chain_id"],
            "seq": row["chain_seq"],
            "prev_id": peer_ids[idx - 1] if idx > 0 else None,
            "next_id": peer_ids[idx + 1] if idx + 1 < len(peer_ids) else None,
            "peers": [dict(p) for p in peers],
        }
    return d


# ---------- 策略 ----------

def get_policy(conn: sqlite3.Connection, day: str | None = None) -> dict | None:
    day = day or today_str()
    row = conn.execute(
        "SELECT policy_date, rule, rule_name, statement, created_at "
        "FROM policies WHERE policy_date = ?",
        (day,),
    ).fetchone()
    return dict(row) if row else None


def _compose_statement(day: str, rule: str, note: str) -> str:
    text = (
        f"{day} 生效规矩：{RULES[rule]}。"
        + ("同指纹告警一律收成同一张处置单。" if rule == "merge"
           else "同指纹告警各自留单，处置单之间以链条互指。")
    )
    note = (note or "").strip()
    return f"{text} 备注：{note}" if note else text


def set_policy(conn: sqlite3.Connection, rule: str, note: str = "") -> dict:
    rule = (rule or "").strip().lower()
    if rule not in RULES:
        raise DomainError(400, "策略规矩必须是 merge（同指纹收成一单）或 chain（分单再串联）")
    day = today_str()
    conn.execute("BEGIN IMMEDIATE")
    try:
        open_n = conn.execute(
            f"SELECT COUNT(*) AS c FROM tickets WHERE status IN (?, ?)",
            OPEN_TICKET_STATES,
        ).fetchone()["c"]
        if open_n > 0:
            raise DomainError(400, "处置尚未收口，禁止改动策略说明")
        if get_policy(conn, day):
            raise DomainError(400, "当日策略已生效，当天不许换")
        statement = _compose_statement(day, rule, note)
        conn.execute(
            "INSERT INTO policies (policy_date, rule, rule_name, statement) "
            "VALUES (?,?,?,?)",
            (day, rule, RULES[rule], statement),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_policy(conn, day)


# ---------- 告警 ----------

def list_alerts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, title, fingerprint, severity, status, created_at "
        "FROM alerts ORDER BY id"
    ).fetchall()
    return [_alert_dict(conn, r) for r in rows]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, title, fingerprint, severity, status, created_at "
        "FROM alerts WHERE id = ?",
        (alert_id,),
    ).fetchone()
    if not row:
        return None
    d = _alert_dict(conn, row)
    if d["ticket_id"]:
        t = conn.execute(
            "SELECT * FROM tickets WHERE id = ?", (d["ticket_id"],)
        ).fetchone()
        d["ticket"] = _ticket_dict(conn, t)
    d["claim_history"] = [
        dict(r)
        for r in conn.execute(
            "SELECT operator, result, created_at FROM claim_attempts "
            "WHERE alert_id = ? ORDER BY id",
            (alert_id,),
        ).fetchall()
    ]
    return d


def ingest_alert(
    conn: sqlite3.Connection, title: str, fingerprint: str, severity: str = ""
) -> dict:
    title = (title or "").strip()
    fingerprint = (fingerprint or "").strip()
    severity = (severity or "").strip()
    if not title or not fingerprint:
        raise DomainError(400, "告警标题与指纹不能为空")
    conn.execute("BEGIN IMMEDIATE")
    try:
        cur = conn.execute(
            "INSERT INTO alerts (title, fingerprint, severity, status) "
            "VALUES (?,?,?,?)",
            (title, fingerprint, severity, ALERT_PENDING),
        )
        new_id = cur.lastrowid
        # 同指纹旧处置单已结案 → 卡片回到待复核，旧结案不得继续充当完成
        conn.execute(
            f"UPDATE tickets SET status = ?, closed_at = NULL "
            "WHERE fingerprint = ? AND status = ?",
            (TICKET_REVIEW, fingerprint, TICKET_CLOSED),
        )
        conn.execute(
            "UPDATE alerts SET status = ? WHERE id IN ("
            "SELECT ta.alert_id FROM ticket_alerts ta "
            "JOIN tickets t ON t.id = ta.ticket_id "
            "WHERE t.fingerprint = ? AND t.status = ?)",
            (ALERT_REVIEW, fingerprint, TICKET_REVIEW),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_alert(conn, new_id)


# ---------- 认领 / 处置单 ----------

def claim_alert(conn: sqlite3.Connection, alert_id: int, operator: str) -> dict:
    operator = (operator or "").strip()
    if not operator:
        raise DomainError(400, "认领动作必须带操作员名")
    conn.execute("BEGIN IMMEDIATE")
    contention_committed = False
    try:
        row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        if not row:
            raise DomainError(404, "告警不存在")
        if not row["severity"]:
            raise DomainError(400, "级别空缺的告警禁止认领与合并")
        policy = get_policy(conn)
        if not policy:
            raise DomainError(400, "当日策略尚未选定，无法形成处置单")

        occupied = conn.execute(
            "SELECT ticket_id FROM ticket_alerts WHERE alert_id = ?", (alert_id,)
        ).fetchone()
        if occupied:
            # 两人抢同一条：后来这笔记争抢失败，原认领不动
            conn.execute(
                "INSERT INTO claim_attempts (alert_id, operator, result) "
                "VALUES (?,?, 'failed')",
                (alert_id, operator),
            )
            conn.commit()
            contention_committed = True
            raise DomainError(409, "争抢失败：该告警已被认领进处置单")

        fp = row["fingerprint"]
        if policy["rule"] == "merge":
            ticket = conn.execute(
                "SELECT * FROM tickets WHERE fingerprint = ? AND status IN (?, ?) "
                "ORDER BY id LIMIT 1",
                (fp, *OPEN_TICKET_STATES),
            ).fetchone()
            if ticket:
                ticket_id = ticket["id"]
            else:
                ticket_id = conn.execute(
                    "INSERT INTO tickets (fingerprint, mode, status, owner) "
                    "VALUES (?, 'merge', ?, ?)",
                    (fp, TICKET_HANDLING, operator),
                ).lastrowid
        else:
            last = conn.execute(
                "SELECT * FROM tickets WHERE fingerprint = ? "
                "ORDER BY chain_seq DESC, id DESC LIMIT 1",
                (fp,),
            ).fetchone()
            seq = (last["chain_seq"] + 1) if last else 1
            ticket_id = conn.execute(
                "INSERT INTO tickets (fingerprint, mode, status, owner, chain_seq) "
                "VALUES (?, 'chain', ?, ?, ?)",
                (fp, TICKET_HANDLING, operator, seq),
            ).lastrowid
            if not last or not last["chain_id"]:
                conn.execute(
                    "UPDATE tickets SET chain_id = ? WHERE id = ?",
                    (f"c{ticket_id}", ticket_id),
                )
            else:
                conn.execute(
                    "UPDATE tickets SET chain_id = ? WHERE id = ?",
                    (last["chain_id"], ticket_id),
                )

        conn.execute(
            "INSERT INTO ticket_alerts (ticket_id, alert_id) VALUES (?, ?)",
            (ticket_id, alert_id),
        )
        conn.execute(
            "INSERT INTO claim_attempts (alert_id, operator, result) "
            "VALUES (?, ?, 'success')",
            (alert_id, operator),
        )
        conn.execute(
            "UPDATE alerts SET status = ? WHERE id = ?",
            (ALERT_HANDLING, alert_id),
        )
        conn.commit()
    except Exception:
        # 争抢失败的留痕已提交，不能再回滚
        if not contention_committed:
            conn.rollback()
        raise
    ticket_row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return _ticket_dict(conn, ticket_row)


def list_tickets(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute("SELECT * FROM tickets ORDER BY id").fetchall()
    return [_ticket_dict(conn, r) for r in rows]


def get_ticket(conn: sqlite3.Connection, ticket_id: int) -> dict | None:
    row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
    return _ticket_dict(conn, row) if row else None


def submit_ticket(
    conn: sqlite3.Connection, ticket_id: int, mode: str, conclusion: str = ""
) -> dict:
    mode = (mode or "").strip().lower()
    if mode not in RULES:
        raise DomainError(400, "实际走法必须是 merge（同指纹收成一单）或 chain（分单再串联）")
    conn.execute("BEGIN IMMEDIATE")
    try:
        row = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if not row:
            raise DomainError(404, "处置单不存在")
        if row["status"] == TICKET_CLOSED:
            raise DomainError(400, "处置单已结案，请勿重复提交")
        policy = get_policy(conn)
        if not policy:
            raise DomainError(400, "当日策略尚未选定，无法提交处置")
        # 实际走法必须与当日策略说明对得上，否则服务端拦下
        if mode != policy["rule"] or row["mode"] != policy["rule"] or mode != row["mode"]:
            raise DomainError(
                400,
                f"走法不符：实际走法（{RULES.get(mode, mode)}）"
                f"与当日策略说明（{policy['rule_name']}）不一致，服务端拦下",
            )
        conn.execute(
            "UPDATE tickets SET status = ?, closed_at = datetime('now'), "
            "conclusion = ? WHERE id = ?",
            (TICKET_CLOSED, (conclusion or "").strip(), ticket_id),
        )
        conn.execute(
            "UPDATE alerts SET status = ? WHERE id IN ("
            "SELECT alert_id FROM ticket_alerts WHERE ticket_id = ?)",
            (ALERT_CLOSED, ticket_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return get_ticket(conn, ticket_id)


# ---------- 台面总览 ----------

def board_snapshot(conn: sqlite3.Connection) -> dict:
    policy = get_policy(conn)
    counts = {
        "pending": conn.execute(
            "SELECT COUNT(*) AS c FROM alerts WHERE status = ?", (ALERT_PENDING,)
        ).fetchone()["c"],
        "handling": conn.execute(
            "SELECT COUNT(*) AS c FROM tickets WHERE status = ?", (TICKET_HANDLING,)
        ).fetchone()["c"],
        "review": conn.execute(
            "SELECT COUNT(*) AS c FROM tickets WHERE status = ?", (TICKET_REVIEW,)
        ).fetchone()["c"],
        "closed": conn.execute(
            "SELECT COUNT(*) AS c FROM tickets WHERE status = ?", (TICKET_CLOSED,)
        ).fetchone()["c"],
    }
    alerts = list_alerts(conn)
    tickets = list_tickets(conn)
    contentions = [
        dict(r)
        for r in conn.execute(
            "SELECT ca.alert_id, ca.operator, ca.created_at, a.fingerprint, a.title "
            "FROM claim_attempts ca JOIN alerts a ON a.id = ca.alert_id "
            "WHERE ca.result = 'failed' ORDER BY ca.id DESC"
        ).fetchall()
    ]
    return {
        "policy": policy,
        "counts": counts,
        "alerts": alerts,
        "tickets": tickets,
        "contentions": contentions,
        "rules": [{"code": k, "name": v} for k, v in RULES.items()],
    }
