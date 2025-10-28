#!/usr/bin/env python3
"""
Quick script to verify database schema.
"""
import sys
sys.path.insert(0, '/Users/jason/Sync/code/Personal/api-gatekeeper')

from src.utils import get_db_connection

db = get_db_connection(verbose=False)

with db.get_cursor(commit=False) as cursor:
    # Get all tables
    cursor.execute("""
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'public'
        ORDER BY tablename
    """)
    tables = cursor.fetchall()

    print("Tables in database:")
    for table in tables:
        print(f"  - {table[0]}")

    # Get column info for clients table
    cursor.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'clients'
        ORDER BY ordinal_position
    """)
    print("\nClients table columns:")
    for col in cursor.fetchall():
        nullable = "NULL" if col[2] == 'YES' else "NOT NULL"
        print(f"  - {col[0]} ({col[1]}) {nullable}")

    # Get column info for client_permissions table
    cursor.execute("""
        SELECT column_name, data_type, is_nullable
        FROM information_schema.columns
        WHERE table_name = 'client_permissions'
        ORDER BY ordinal_position
    """)
    print("\nClient Permissions table columns:")
    for col in cursor.fetchall():
        nullable = "NULL" if col[2] == 'YES' else "NOT NULL"
        print(f"  - {col[0]} ({col[1]}) {nullable}")

db.close()
print("\n✓ Schema verification complete")
