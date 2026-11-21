"""
Pre-start script to verify PostgreSQL database connection before running migrations.
"""
import logging
import sys
import time

from sqlalchemy import text

from app.database import engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("pre_start")

MAX_RETRIES = 30
RETRY_INTERVAL_SECONDS = 2


def check_db_connection() -> None:
    """
    Verify database connection. Retries if the database is starting up.
    Exits with code 1 if connection fails after MAX_RETRIES.
    """
    logger.info("Verifying PostgreSQL database connection...")
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            logger.info("Database connection established successfully.")
            return
        except Exception as exc:
            if attempt == MAX_RETRIES:
                logger.error("Failed to connect to database after %d attempts: %s", MAX_RETRIES, exc)
                sys.exit(1)
            logger.warning(
                "Database not ready yet (attempt %d/%d). Retrying in %ds... Error: %s",
                attempt,
                MAX_RETRIES,
                RETRY_INTERVAL_SECONDS,
                exc,
            )
            time.sleep(RETRY_INTERVAL_SECONDS)


if __name__ == "__main__":
    check_db_connection()
