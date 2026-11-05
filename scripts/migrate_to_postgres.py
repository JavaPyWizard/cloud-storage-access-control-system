import sqlite3
from getpass import getpass
from pathlib import Path

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import URL

from app.db import Base

SQLITE_PATH = Path("cloudguard_sim.db")

TABLES = ["users", "objects", "audits"]


def create_postgres_engine():
    password = getpass("PostgreSQL password: ")

    url = URL.create(
        drivername="postgresql+psycopg",
        username="aegisvault_user",
        password=password,
        host="127.0.0.1",
        port=5432,
        database="aegisvault_db",
    )

    return create_engine(url, pool_pre_ping=True)


def read_sqlite_data():
    if not SQLITE_PATH.is_file():
        raise RuntimeError("SQLite database not found.")

    connection = sqlite3.connect(
        f"file:{SQLITE_PATH.resolve()}?mode=ro",
        uri=True,
    )
    connection.row_factory = sqlite3.Row

    try:
        data = {}

        for table in TABLES:
            rows = connection.execute(f'SELECT * FROM "{table}" ORDER BY id').fetchall()

            data[table] = [dict(row) for row in rows]

        if table == "audits":
            for record in data[table]:
                record["allowed"] = bool(record["allowed"])
                record["simulated"] = bool(record["simulated"])

            print(f"SQLite {table}: {len(data[table])}")

        return data

    finally:
        connection.close()


def migrate():
    print("\nAEGISVAULT POSTGRESQL MIGRATION\n")

    data = read_sqlite_data()

    engine = create_postgres_engine()

    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())

        for table in TABLES:
            if table in existing_tables:
                raise RuntimeError(
                    f"PostgreSQL table '{table}' already exists. "
                    "Migration cancelled to protect existing data."
                )

        Base.metadata.create_all(bind=engine)

        try:
            with engine.begin() as connection:
                for table in TABLES:
                    rows = data[table]

                    if not rows:
                        continue

                    columns = list(rows[0].keys())

                    column_sql = ", ".join(f'"{column}"' for column in columns)

                    value_sql = ", ".join(f":{column}" for column in columns)

                    statement = text(
                        f'INSERT INTO "{table}" ({column_sql}) VALUES ({value_sql})'
                    )

                    connection.execute(statement, rows)

                    print(f"Migrated {table}: {len(rows)} records")

                for table in TABLES:
                    result = connection.execute(
                        text(f'SELECT COUNT(*) FROM "{table}"')
                    ).scalar_one()

                    if result != len(data[table]):
                        raise RuntimeError(f"Verification failed for {table}")

                for table in TABLES:
                    connection.execute(
                        text(
                            f"""
                            SELECT setval(
                                pg_get_serial_sequence(
                                    '{table}', 'id'
                                ),
                                COALESCE(
                                    (SELECT MAX(id) FROM "{table}"),
                                    1
                                ),
                                (SELECT COUNT(*) > 0 FROM "{table}")
                            )
                            """
                        )
                    )

        except Exception:
            print("Migration failed. Data transaction rolled back.")
            raise

        print("\nPOSTGRESQL VERIFICATION")

        with engine.connect() as connection:
            for table in TABLES:
                count = connection.execute(
                    text(f'SELECT COUNT(*) FROM "{table}"')
                ).scalar_one()

                print(f"{table}: {count}")

        print("\nMIGRATION SUCCESSFUL")
        print("SQLite database remains unchanged.")
        print("Do not switch .env until verification is complete.")

    finally:
        engine.dispose()


if __name__ == "__main__":
    migrate()
