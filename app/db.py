import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.config import Config

SEED_ALERTS = [
    ("主机异常登录", "auth.bruteforce", "高", "待分流"),
    ("容器逃逸嫌疑", "runtime.escape", "高", "待分流"),
    ("证书即将过期", "tls.expiry", "中", "待分流"),
    ("异常外联探测", "net.exfil", "高", "待分流"),
    ("策略配置漂移", "policy.drift", "中", "待分流"),
]


def connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or Config.database()
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


@contextmanager
def get_db(db_path: str | None = None):
    conn = connect(db_path)
    try:
        yield conn
        conn.commit()
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
              severity TEXT NOT NULL,
              status TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT (datetime('now'))
            );
            CREATE TABLE IF NOT EXISTS meta (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            );
            """
        )
        n = conn.execute("SELECT COUNT(*) AS c FROM alerts").fetchone()["c"]
        if n == 0:
            conn.executemany(
                "INSERT INTO alerts (title, fingerprint, severity, status) VALUES (?,?,?,?)",
                SEED_ALERTS,
            )
            conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES ('lab_name', ?)",
                ("安全事件分流台",),
            )


def list_alerts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT id, title, fingerprint, severity, status, created_at FROM alerts ORDER BY id"
    ).fetchall()
    return [dict(r) for r in rows]


def get_alert(conn: sqlite3.Connection, alert_id: int) -> dict | None:
    row = conn.execute(
        "SELECT id, title, fingerprint, severity, status, created_at FROM alerts WHERE id = ?",
        (alert_id,),
    ).fetchone()
    return dict(row) if row else None
