import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Docker passes real env vars directly (load_dotenv default is non-
# overriding, so this is a no-op there). Local `uvicorn` runs need this to
# pick up backend/.env - db.py is imported before any other module reads
# an env var (e.g. auth.py imports `from app.db import get_db` before its
# own os.environ.get("JWT_SECRET_KEY") line), so this has to run here,
# first, not in main.py.
load_dotenv()

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./sentraops.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def run_migrations(url: str | None = None) -> None:
    """Applies all pending Alembic migrations. Replaces the old
    Base.metadata.create_all() approach, which only creates missing tables
    and silently does nothing when an existing table needs a new column -
    that gap bit this project already (see README history / step-5 audit).

    Tests pass an explicit `url` (their own per-test sqlite file) so they
    exercise the same migration path as production instead of a separate
    create_all() shortcut that could silently drift from the migrations."""
    from pathlib import Path

    from alembic import command
    from alembic.config import Config

    backend_dir = Path(__file__).resolve().parent.parent
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url or DATABASE_URL)
    command.upgrade(cfg, "head")


def init_db() -> None:
    import app.db_models  # noqa: F401  (ensure models are registered on Base.metadata)

    run_migrations()
