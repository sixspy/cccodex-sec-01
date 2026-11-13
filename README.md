# cc-sec-lab

CC_Codex 二期（26.11）**安全**基线：**安全事件分流台**（FastAPI + Vue 3 SPA + SQLite）。

## 领域

- **所属领域**：安全  
- **子方向**：安全风控与策略 / 终端与运行时告警分流  

## 技术栈

- Python 3.12+、FastAPI、Uvicorn、SQLite  
- Vue 3（CDN，Composition API，单页）  
- 页面风格：冷色工业台账（青石色强调，浅灰底，等宽指纹）  
- pytest + httpx  

## 本地运行

```powershell
cd claude-workspace\cc-sec-lab
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest
python run.py
```

浏览器 http://127.0.0.1:5800/login · **admin / 123456**。

## Docker

```powershell
docker compose up -d --build
```

健康检查通过后打开登录页。

## 基线能力

登录、告警列表、告警详情（指纹 / 级别 / 状态）。后续单轮题在此上叠加合并、处置窗口、并发认领等。
