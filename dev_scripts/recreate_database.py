#!/usr/bin/env python
"""
Recreate database with updated schema (drops and recreates all tables).

WARNING: This will DELETE ALL DATA in the database!
Only use this during development/alpha phase.

Usage:
  python dev_scripts/recreate_database.py                 # Recreate main 'api_auth_admin' database
  python dev_scripts/recreate_database.py --test-db       # Recreate test 'api_auth_admin_test' database
"""

import os
import sys
import argparse
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv


def main():
    """Recreate api_auth_admin database tables"""
    # Load environment variables from .env file
    load_dotenv()

    parser = argparse.ArgumentParser(description='Recreate API_AUTH_ADMIN database tables')
    parser.add_argument('--test-db', action='store_true',
                       help='Recreate api_auth_admin_test database instead of main api_auth_admin database')
    parser.add_argument('--yes', '-y', action='store_true',
                       help='Skip confirmation prompt')
    args = parser.parse_args()

    pg_host = os.environ.get('POSTGRES_HOST', 'localhost')
    pg_port = os.environ.get('POSTGRES_PORT', '5432')

    if args.test_db:
        api_auth_admin_db = 'api_auth_admin_test'
        print("Recreating TEST database tables in 'api_auth_admin_test'...")
    else:
        api_auth_admin_db = os.environ.get('API_AUTH_ADMIN_PG_DB', 'api_auth_admin')
        print(f"Recreating database tables in '{api_auth_admin_db}'...")

    api_auth_admin_user = os.environ.get('API_AUTH_ADMIN_PG_USER', 'api_auth_admin')
    api_auth_admin_password = os.environ.get('API_AUTH_ADMIN_PG_PASSWORD', None)

    if api_auth_admin_password is None:
        print("Error: API_AUTH_ADMIN_PG_PASSWORD environment variable is required")
        sys.exit(1)

    # Confirmation prompt (unless --yes flag)
    if not args.yes and not args.test_db:
        print("\n⚠️  WARNING: This will DELETE ALL DATA in the database!")
        print(f"Database: {api_auth_admin_db}")
        print(f"Host: {pg_host}:{pg_port}")
        response = input("\nAre you sure you want to continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Aborted.")
            sys.exit(0)

    try:
        print(f"\nConnecting to '{api_auth_admin_db}' at {pg_host}:{pg_port} as {api_auth_admin_user}...")
        conn = psycopg2.connect(
            host=pg_host,
            port=pg_port,
            database=api_auth_admin_db,
            user=api_auth_admin_user,
            password=api_auth_admin_password
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)

        with conn.cursor() as cursor:
            # Drop all tables in correct order (respecting foreign keys)
            print("\nDropping existing tables...")
            cursor.execute("DROP TABLE IF EXISTS client_permissions CASCADE")
            print("✓ Dropped client_permissions")
            cursor.execute("DROP TABLE IF EXISTS clients CASCADE")
            print("✓ Dropped clients")
            cursor.execute("DROP TABLE IF EXISTS routes CASCADE")
            print("✓ Dropped routes")

            # Get schema file path
            repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            schema_path = os.path.join(repo_root, 'src', 'database', 'schema.sql')
            if not os.path.exists(schema_path):
                print(f"Error: schema file not found at {schema_path}")
                sys.exit(1)

            # Read and apply schema
            with open(schema_path, 'r', encoding='utf-8') as f:
                schema_sql = f.read()

            print("\nApplying updated schema...")
            cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")
            cursor.execute(schema_sql)
            print("✓ Schema applied")

            # Verify tables were created
            cursor.execute("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'public'
                AND table_type = 'BASE TABLE'
                ORDER BY table_name
            """)
            tables = cursor.fetchall()
            print("\n✓ Tables created:")
            for table in tables:
                print(f"  - {table[0]}")

        conn.close()
        print("\n✓ Database recreation complete")
        print(f"Database: {api_auth_admin_db}")
        print(f"User: {api_auth_admin_user}")
        print(f"Host: {pg_host}:{pg_port}")
        print("\nYou can now run management scripts to create routes, clients, and permissions.")

    except psycopg2.Error as e:
        print(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
