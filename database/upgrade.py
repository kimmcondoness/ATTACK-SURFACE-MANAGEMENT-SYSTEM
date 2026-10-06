"""Bring an existing database up to date without losing data.

`db.create_all()` only creates tables that are missing; it never adds a column to a
table that already exists. Databases created before continuous monitoring therefore
lack the new columns, so this adds them (and any missing table) in place. It only ever
adds, and it is safe to run on every start-up.
"""

from sqlalchemy import inspect, text

# (table, column, column definition). Written to work on both MySQL and SQLite.
COLUMN_UPGRADES = (
    ("authorized_targets", "monitor_interval_days", "INTEGER NULL"),
    ("authorized_targets", "monitor_last_run_at", "DATETIME NULL"),
    ("authorized_targets", "monitor_set_by", "INTEGER NULL"),
    ("authorized_targets", "monitor_set_at", "DATETIME NULL"),
    ("assets", "last_seen_at", "DATETIME NULL"),
    ("assets", "status", "VARCHAR(20) NOT NULL DEFAULT 'active'"),
    ("assets", "missed_runs", "INTEGER NOT NULL DEFAULT 0"),
    ("users", "last_seen_at", "DATETIME NULL"),
)


def upgrade_schema(db) -> list:
    """Add whatever is missing. Returns a description of each change made."""
    import models  # noqa: F401  registers every table with SQLAlchemy; at start-up nothing has imported them yet

    if "authorized_targets" not in inspect(db.engine).get_table_names():
        return []   # a brand-new database: create_all() builds everything from the models

    applied = []
    before = set(inspect(db.engine).get_table_names())
    db.create_all()   # creates tables that do not exist yet (e.g. monitor_events, monitor_runs, report_shares)
    applied += [f"created table {name}" for name in sorted(set(inspect(db.engine).get_table_names()) - before)]

    inspector = inspect(db.engine)
    for table, column, definition in COLUMN_UPGRADES:
        if table not in inspector.get_table_names():
            continue
        if column in {c["name"] for c in inspector.get_columns(table)}:
            continue
        with db.engine.begin() as connection:
            connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {definition}"))
        applied.append(f"added {table}.{column}")
    return applied
