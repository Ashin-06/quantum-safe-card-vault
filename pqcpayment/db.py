"""Where state lives: SQLite by default, Postgres when PQCPAYMENT_DATABASE_URL says so.

Schema changes are numbered SQL files in `migrations/` (001_init.sql, 002_...). Each runs
once, in its own transaction, and is recorded in `schema_migrations`; `connect` applies
any that are missing, and `python -m pqcpayment migrate` does the same on its own. Write
them in SQL both databases accept (TEXT, INTEGER, BIGINT; no BLOB/BYTEA, no REAL money).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.pool import StaticPool

MIGRATIONS = Path(__file__).with_name("migrations")


def connect(url: str) -> Engine:
    """An engine for `url` with every migration applied."""
    eng = engine(url)
    migrate(eng)
    return eng


def engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        path = url.split("///", 1)[1] if "///" in url else ""
        if path and path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        extra = {} if path and path != ":memory:" else {"poolclass": StaticPool}  # one shared in-memory DB
        eng = create_engine(url, connect_args={"check_same_thread": False}, **extra)

        @event.listens_for(eng, "connect")
        def _pragmas(conn, _):
            cur = conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.close()
    else:
        eng = create_engine(url.replace("postgresql://", "postgresql+psycopg://", 1), pool_pre_ping=True)
    return eng


def migrate(eng: Engine) -> list[str]:
    """Apply missing migrations in order; returns the files applied.
    ponytail: two replicas starting at once both try; the loser's transaction fails on the
    schema_migrations key and it restarts. Run `migrate` as a deploy step if that matters."""
    with eng.begin() as c:
        c.execute(text("CREATE TABLE IF NOT EXISTS schema_migrations "
                       "(version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)"))
        done = {r[0] for r in c.execute(text("SELECT version FROM schema_migrations"))}
    applied = []
    for f in sorted(MIGRATIONS.glob("*.sql")):
        version = int(f.name.split("_", 1)[0])
        if version in done:
            continue
        with eng.begin() as c:
            sql = re.sub(r"--.*", "", f.read_text(encoding="utf-8"))
            for stmt in sql.split(";"):  # so: no semicolons or "--" inside string literals
                if stmt.strip():
                    c.exec_driver_sql(stmt)
            c.execute(text("INSERT INTO schema_migrations VALUES (:v, :n, :t)"),
                      {"v": version, "n": f.name, "t": datetime.now(timezone.utc).isoformat()})
        applied.append(f.name)
    return applied
