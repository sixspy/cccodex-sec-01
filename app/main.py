import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from itsdangerous import BadSignature, URLSafeSerializer

from app.config import Config
from app.db import (
    DomainError,
    board_snapshot,
    claim_alert,
    get_alert,
    get_db,
    get_ticket,
    get_policy,
    ingest_alert,
    init_db,
    list_alerts,
    list_tickets,
    set_policy,
    submit_ticket,
)

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"
serializer = URLSafeSerializer(Config.SECRET, salt="cc-sec-session")

app = FastAPI(title="cc-sec-lab")
app.mount("/static", StaticFiles(directory=str(STATIC)), name="static")


def _read_session(request: Request) -> dict:
    raw = request.cookies.get("sec_session")
    if not raw:
        return {}
    try:
        data = serializer.loads(raw)
        return data if isinstance(data, dict) else {}
    except BadSignature:
        return {}


def require_user(request: Request) -> str:
    user = _read_session(request).get("user")
    if user != Config.ADMIN_USER:
        raise HTTPException(status_code=401, detail="未登录")
    return user


@app.on_event("startup")
def _startup() -> None:
    init_db()


@app.get("/")
def root(request: Request):
    if _read_session(request).get("user") == Config.ADMIN_USER:
        return RedirectResponse("/app/", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/login")
def login_page():
    return FileResponse(STATIC / "login.html")


@app.get("/app/")
def spa_page(request: Request):
    if _read_session(request).get("user") != Config.ADMIN_USER:
        return RedirectResponse("/login", status_code=302)
    return FileResponse(STATIC / "index.html")


@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    user = str(body.get("username", "")).strip()
    pwd = str(body.get("password", ""))
    if user != Config.ADMIN_USER or pwd != Config.ADMIN_PASSWORD:
        return JSONResponse({"ok": False, "error": "账号或密码错误"}, status_code=400)
    resp = JSONResponse({"ok": True, "user": user})
    resp.set_cookie(
        "sec_session",
        serializer.dumps({"user": user}),
        httponly=True,
        samesite="lax",
    )
    return resp


@app.post("/api/logout")
def api_logout():
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("sec_session")
    return resp


@app.get("/api/me")
def api_me(user: str = Depends(require_user)):
    return {"user": user, "lab": "安全事件分流台"}


# ---------- 台面总览 ----------

@app.get("/api/board")
def api_board(user: str = Depends(require_user)):
    with get_db() as conn:
        return board_snapshot(conn)


# ---------- 策略 ----------

@app.get("/api/policy")
def api_policy_get(user: str = Depends(require_user)):
    with get_db() as conn:
        return {"policy": get_policy(conn)}


@app.post("/api/policy")
async def api_policy_set(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    rule = str(body.get("rule", "")).strip()
    note = str(body.get("note", "")).strip()
    with get_db() as conn:
        try:
            policy = set_policy(conn, rule, note)
        except DomainError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {"ok": True, "policy": policy}


# ---------- 告警 ----------

@app.get("/api/alerts")
def api_alerts(user: str = Depends(require_user)):
    with get_db() as conn:
        return {"items": list_alerts(conn)}


@app.get("/api/alerts/{alert_id}")
def api_alert_detail(alert_id: int, user: str = Depends(require_user)):
    with get_db() as conn:
        item = get_alert(conn, alert_id)
    if not item:
        raise HTTPException(status_code=404, detail="告警不存在")
    return item


@app.post("/api/alerts")
async def api_ingest(request: Request, user: str = Depends(require_user)):
    body = await request.json()
    title = str(body.get("title", "")).strip()
    fingerprint = str(body.get("fingerprint", "")).strip()
    severity = str(body.get("severity", "")).strip()
    with get_db() as conn:
        try:
            item = ingest_alert(conn, title, fingerprint, severity)
        except DomainError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {"ok": True, "item": item}


@app.post("/api/alerts/{alert_id}/claim")
async def api_claim(alert_id: int, request: Request, user: str = Depends(require_user)):
    body = await request.json() if request.headers.get("content-type") else {}
    operator = str((body or {}).get("operator", "")).strip()
    with get_db() as conn:
        try:
            ticket = claim_alert(conn, alert_id, operator)
        except DomainError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {"ok": True, "ticket": ticket}


# ---------- 处置单 ----------

@app.get("/api/tickets")
def api_tickets(user: str = Depends(require_user)):
    with get_db() as conn:
        return {"items": list_tickets(conn)}


@app.get("/api/tickets/{ticket_id}")
def api_ticket_detail(ticket_id: int, user: str = Depends(require_user)):
    with get_db() as conn:
        item = get_ticket(conn, ticket_id)
    if not item:
        raise HTTPException(status_code=404, detail="处置单不存在")
    return item


@app.post("/api/tickets/{ticket_id}/submit")
async def api_ticket_submit(
    ticket_id: int, request: Request, user: str = Depends(require_user)
):
    body = await request.json()
    mode = str(body.get("mode", "")).strip()
    conclusion = str(body.get("conclusion", "")).strip()
    with get_db() as conn:
        try:
            ticket = submit_ticket(conn, ticket_id, mode, conclusion)
        except DomainError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message)
    return {"ok": True, "ticket": ticket}


def create_app() -> FastAPI:
    return app


if __name__ == "__main__":
    import uvicorn

    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5800"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False)
