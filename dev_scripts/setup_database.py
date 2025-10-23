#!/usr/bin/env python
"""
Database setup script for API_AUTH_ADMIN
Creates the api_auth_admin database and user with proper permissions, then applies database/schema.sql

Usage:
  python setup_database.py                 # Sets up main 'api_auth_admin' database
  python setup_database.py --test-db       # Sets up test 'api_auth_admin_test' database
"""

import os
import sys
import argparse
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv


def main():
    """Setup api_auth_admin database and user"""
    # Load environment variables from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description='Setup API_AUTH_ADMIN database')
    parser.add_argument('--test-db', action='store_true',
                       help='Create api_auth_admin_test database instead of main api_auth_admin database')
    args = parser.parse_args()

    pg_host = os.environ.get('POSTGRES_HOST', 'localhost')
    pg_port = os.environ.get('POSTGRES_PORT', '5432')
    pg_user = os.environ.get('POSTGRES_USER', 'postgres')
    pg_password = os.environ.get('PG_PASSWORD', None)

    if args.test_db:
        api_auth_admin_db = 'api_auth_admin_test'
        print("Setting up TEST database 'api_auth_admin_test'...")
    else:
        api_auth_admin_db = os.environ.get('API_AUTH_ADMIN_PG_DB', 'api_auth_admin')
    api_auth_admin_user = os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin')
    api_auth_admin_password = os.environ.get('API_AUTH_ADMIN_PG_PASSWORD', None)

    if pg_password is None:
        print("Error: PG_PASSWORD environment variable is required")
        sys.exit(1)
    if api_auth_admin_password is None:
        print("Error: API_AUTH_ADMIN_PG_PASSWORD environment variable is required")
        sys.exit(1)

    print(f"Setting up database '{api_auth_admin_db}' and user '{api_auth_admin_user}'...")
    print(f"Connecting to PostgreSQL at {pg_host}:{pg_port} as {pg_user}")

    try:
        conn = psycopg2.connect(
            host=pg_host,
            port=pg_port,
            database='postgres',
            user=pg_user,
            password=pg_password
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        with conn.cursor() as cursor:
            cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (api_auth_admin_user,))
            if not cursor.fetchone():
                print(f"Creating user '{api_auth_admin_user}'...")
                cursor.execute(f"CREATE USER {api_auth_admin_user} WITH PASSWORD %s", (api_auth_admin_password,))
                print(f"✓ User '{api_auth_admin_user}' created")
            else:
                print(f"✓ User '{api_auth_admin_user}' already exists")

            cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (api_auth_admin_db,))
            if not cursor.fetchone():
                print(f"Creating database '{api_auth_admin_db}'...")
                cursor.execute(f"CREATE DATABASE {api_auth_admin_db} OWNER {api_auth_admin_user}")
                print(f"✓ Database '{api_auth_admin_db}' created")
            else:
                print(f"✓ Database '{api_auth_admin_db}' already exists")

            print("Setting permissions...")
            cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {api_auth_admin_db} TO {api_auth_admin_user}")
            print(f"✓ Granted all privileges on database '{api_auth_admin_db}' to user '{api_auth_admin_user}'")

        conn.close()

        print(f"\nConnecting as '{api_auth_admin_user}' to apply schema...")
        api_auth_admin_conn = psycopg2.connect(
            host=pg_host,
            port=pg_port,
            database=api_auth_admin_db,
            user=api_auth_admin_user,
            password=api_auth_admin_password
        )
        api_auth_admin_conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        schema_path = os.path.join(repo_root, 'src', 'database', 'schema.sql')
        if not os.path.exists(schema_path):
            print(f"Error: schema file not found at {schema_path}")
            sys.exit(1)

        with open(schema_path, 'r', encoding='utf-8') as f:
            schema_sql = f.read()

        with api_auth_admin_conn.cursor() as cursor:
            print("Ensuring required extensions...")
            cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            print(f"Applying schema from {schema_path}...")
            cursor.execute(schema_sql)
            print("✓ Schema applied")

        api_auth_admin_conn.close()
        print("✓ Database setup complete")
        print(f"Database: {api_auth_admin_db}")
        print(f"User: {api_auth_admin_user}")
        print(f"Host: {pg_host}:{pg_port}")

    except psycopg2.Error as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
