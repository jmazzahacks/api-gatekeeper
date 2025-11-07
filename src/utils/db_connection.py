"""
Database connection utilities for scripts.
"""
import os
import sys
from typing import Optional
from dotenv import load_dotenv

from src.database import AuthServiceDB

# Load environment variables from .env file
load_dotenv()


def get_db_connection(verbose: bool = True) -> AuthServiceDB:
    """
    Create and return a database connection using environment variables.

    Environment variables:
        POSTGRES_HOST: Database host (default: localhost)
        POSTGRES_PORT: Database port (default: 5432)
        API_AUTH_ADMIN_PG_DB: Database name (default: api_auth_admin)
        API_AUTH_ADMIN_PG_USER: Database user (default: api_auth_admin)
        API_AUTH_ADMIN_PG_PASSWORD: Database password (required)

    Args:
        verbose: Whether to print connection status messages

    Returns:
        AuthServiceDB instance

    Raises:
        SystemExit: If required environment variables are missing or connection fails
    """
    db_host = os.environ.get('POSTGRES_HOST', 'localhost')
    db_port = int(os.environ.get('POSTGRES_PORT', '5432'))
    db_name = os.environ.get('API_AUTH_ADMIN_PG_DB', 'api_auth_admin')
    db_user = os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin')
    db_password = os.environ.get('API_AUTH_ADMIN_PG_PASSWORD')

    if not db_password:
        print("Error: API_AUTH_ADMIN_PG_PASSWORD environment variable is required")
        sys.exit(1)

    if verbose:
        print(f"Connecting to database '{db_name}' at {db_host}:{db_port}...")

    try:
        db = AuthServiceDB(
            db_host=db_host,
            db_port=db_port,
            db_name=db_name,
            db_user=db_user,
            db_password=db_password
        )
        if verbose:
            print("✓ Connected\n")
        return db
    except Exception as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)
