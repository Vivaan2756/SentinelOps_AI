"""Database engine, session creation, and connectivity diagnostics."""

from typing import Generator, Tuple
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

# Connect args: short timeout for health checks
connect_args = {}
if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False

engine = create_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    connect_args=connect_args,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """Dependency that yields a database session and safely closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connectivity() -> Tuple[bool, str]:
    """
    Safely probe database connectivity with SELECT 1.
    Never exposes passwords in return messages.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True, "Database connection operational"
    except Exception as exc:
        # Sanitize exception message to ensure no connection credentials or passwords leak
        err_msg = str(exc)
        if "password authentication failed" in err_msg.lower():
            safe_msg = "Database authentication failed (credentials rejected)"
        elif "connection refused" in err_msg.lower() or "timeout" in err_msg.lower():
            safe_msg = "Database host or port unreachable"
        elif "does not exist" in err_msg.lower():
            safe_msg = "Target database does not exist"
        else:
            safe_msg = "Database connection unavailable"
        logger.warning("Database connectivity check failed: %s", safe_msg)
        return False, safe_msg
