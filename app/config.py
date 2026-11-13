import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


class Config:
    ADMIN_USER = "admin"
    ADMIN_PASSWORD = "123456"
    SECRET = os.environ.get("APP_SECRET", "cc-sec-lab-dev")

    @staticmethod
    def database() -> str:
        return os.environ.get(
            "DATABASE_PATH", str(ROOT / "instance" / "sec_lab.db")
        )
