"""
Pytest configuration and fixtures for API Auth Service tests.
CRITICAL: All tests use the api_auth_admin_test database to avoid affecting production data.
"""
import os
import pytest
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

from src.database import AuthServiceDB


load_dotenv()


@pytest.fixture(scope='session')
def test_db_config():
    """
    Provide test database configuration.
    Uses api_auth_admin_test database to avoid affecting production data.
    """
    return {
        'db_host': os.environ.get('POSTGRES_HOST', 'localhost'),
        'db_name': 'api_auth_admin_test',
        'db_user': os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin'),
        'db_password': os.environ['API_AUTH_ADMIN_PG_PASSWORD']
    }


@pytest.fixture(scope='session')
def ensure_test_db_exists(test_db_config):
    """
    Ensure the test database exists before running tests.
    This should have been created by running: python dev_scripts/setup_database.py --test-db
    """
    pg_host = test_db_config['db_host']
    test_db_name = test_db_config['db_name']

    try:
        conn = psycopg2.connect(
            host=pg_host,
            database='postgres',
            user=os.environ.get('POSTGRES_USER', 'postgres'),
            password=os.environ['PG_PASSWORD']
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (test_db_name,)
            )
            if not cursor.fetchone():
                raise Exception(
                    f"Test database '{test_db_name}' does not exist. "
                    f"Please run: python dev_scripts/setup_database.py --test-db"
                )
        conn.close()
        return True
    except psycopg2.Error as e:
        raise Exception(f"Failed to verify test database: {e}")


@pytest.fixture(scope='function')
def db(test_db_config, ensure_test_db_exists):
    """
    Provide a database connection for each test.
    Automatically cleans up all data after each test to ensure isolation.
    """
    database = AuthServiceDB(**test_db_config)

    yield database

    # Cleanup: Delete all data after each test for isolation
    # Order matters due to foreign key constraints
    with database.get_cursor() as cursor:
        cursor.execute("DELETE FROM client_permissions")
        cursor.execute("DELETE FROM clients")
        cursor.execute("DELETE FROM routes")

    database.close()


@pytest.fixture(scope='function')
def clean_db(db):
    """
    Provide a clean database connection with all tables emptied.
    Use this fixture when you want to ensure a completely clean state.
    """
    with db.get_cursor() as cursor:
        cursor.execute("DELETE FROM client_permissions")
        cursor.execute("DELETE FROM clients")
        cursor.execute("DELETE FROM routes")
    return db
