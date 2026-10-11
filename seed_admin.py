import os
import sys
import asyncio

# Safeguard console UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure parent and child directories are on PYTHONPATH
current_dir = os.path.dirname(os.path.abspath(__file__))
sub_dir = os.path.join(current_dir, "threat-agent-platform")
parent_dir = os.path.dirname(current_dir)

for d in [current_dir, sub_dir, parent_dir, os.path.join(parent_dir, "threat-agent-platform")]:
    if os.path.exists(d) and d not in sys.path:
        sys.path.insert(0, d)

# Resolve persistent database path to canonical location
if not os.getenv("DB_PATH"):
    if os.path.exists(os.path.join(sub_dir, "data")):
        os.environ["DB_PATH"] = os.path.join(sub_dir, "data", "sentinel_soc.db")
    elif os.path.exists(os.path.join(current_dir, "data")):
        os.environ["DB_PATH"] = os.path.join(current_dir, "data", "sentinel_soc.db")
    elif os.path.exists(os.path.join(parent_dir, "threat-agent-platform", "data")):
        os.environ["DB_PATH"] = os.path.join(parent_dir, "threat-agent-platform", "data", "sentinel_soc.db")

from src.db.session import init_db, async_session
from src.db.models import User
from src.core.auth import AuthService
from sqlalchemy import select


async def seed():
    await init_db()
    async with async_session() as s:
        stmt = select(User).where(User.username == "admin")
        res = await s.execute(stmt)
        existing = res.scalar_one_or_none()

        if not existing:
            u = User(
                username="admin",
                password_hash=AuthService.get_password_hash("admin123"),
                role="ADMIN",
                active_device_token="manual_seed_device",
            )
            s.add(u)
            await s.commit()
            print("\n[+] Created default user successfully: admin / admin123\n")
        else:
            print("\n[+] User 'admin' already exists in database.\n")


if __name__ == "__main__":
    asyncio.run(seed())
