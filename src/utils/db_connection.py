"""
Database connection utilities for scripts.
"""
import os
import sys
from typing import Optional

from src.database import AuthServiceDB


def get_db_connection(verbose: bool = True) -> AuthServiceDB:
    """
    Create and return a database connection using environment variables.

    Args:
        verbose: Whether to print connection status messages

    Returns:
        AuthServiceDB instance

    Raises:
        SystemExit: If required environment variables are missing or connection fails
    """
    db_host = os.environ.get('POSTGRES_HOST', 'localhost')
    db_name = os.environ.get('API_AUTH_ADMIN_PG_DB', 'api_auth_admin')
    db_user = os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin')
    db_password = os.environ.get('API_AUTH_ADMIN_PG_PASSWORD')

    if not db_password:
        print("Error: API_AUTH_ADMIN_PG_PASSWORD environment variable is required")
        sys.exit(1)

    if verbose:
        print(f"Connecting to database '{db_name}' at {db_host}...")

    try:
        db = AuthServiceDB(
            db_host=db_host,
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
