"""
Database driver for API Authentication Service.
Provides connection pooling and database operations for routes.
"""
from typing import Optional, List
from contextlib import contextmanager
import json
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor

from ..models.route import Route


class AuthServiceDB:
    """Database driver for API authentication service with connection pooling."""

    def __init__(
        self,
        db_host: str,
        db_name: str,
        db_user: str,
        db_password: str,
        min_conn: int = 2,
        max_conn: int = 10
    ):
        """
        Initialize database connection pool.

        Args:
            db_host: PostgreSQL host
            db_name: Database name
            db_user: Database user
            db_password: Database password
            min_conn: Minimum number of connections in pool
            max_conn: Maximum number of connections in pool
        """
        self.pool = ThreadedConnectionPool(
            min_conn,
            max_conn,
            host=db_host,
            database=db_name,
            user=db_user,
            password=db_password
        )

    @contextmanager
    def _get_connection(self):
        """Context manager for getting a connection from the pool."""
        conn = self.pool.getconn()
        try:
            yield conn
        finally:
            self.pool.putconn(conn)

    @contextmanager
    def get_cursor(self, commit: bool = True, cursor_factory=None):
        """
        Context manager for database cursors with automatic commit/rollback.

        Args:
            commit: Whether to commit on success
            cursor_factory: Optional cursor factory (e.g., RealDictCursor)

        Yields:
            Database cursor
        """
        with self._get_connection() as conn:
            cursor = conn.cursor(cursor_factory=cursor_factory)
            try:
                yield cursor
                if commit:
                    conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                cursor.close()

    def load_route_by_id(self, route_id: str) -> Optional[Route]:
        """
        Load a route by its ID.

        Args:
            route_id: Route identifier

        Returns:
            Route object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM routes WHERE route_id = %s",
                (route_id,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return Route.from_dict(dict(result))

    def load_route_by_pattern(self, pattern: str) -> Optional[Route]:
        """
        Load a route by its exact pattern.

        Args:
            pattern: Route pattern

        Returns:
            Route object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM routes WHERE route_pattern = %s",
                (pattern,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return Route.from_dict(dict(result))

    def load_routes_by_service(self, service_name: str) -> List[Route]:
        """
        Load all routes for a specific service.

        Args:
            service_name: Service name

        Returns:
            List of Route objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM routes WHERE service_name = %s ORDER BY route_pattern",
                (service_name,)
            )
            results = cursor.fetchall()
            return [Route.from_dict(dict(row)) for row in results]

    def load_all_routes(self) -> List[Route]:
        """
        Load all routes from the database.

        Returns:
            List of all Route objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM routes ORDER BY service_name, route_pattern")
            results = cursor.fetchall()
            return [Route.from_dict(dict(row)) for row in results]

    def find_matching_routes(self, path: str) -> List[Route]:
        """
        Find all routes that match a given path (exact or wildcard).

        Args:
            path: URL path to match

        Returns:
            List of matching Route objects
        """
        routes = self.load_all_routes()
        return [route for route in routes if route.matches(path)]

    def save_route(self, route: Route) -> None:
        """
        Insert or update a route in the database.

        Args:
            route: Route object to save
        """
        route_dict = route.to_dict()
        # Convert methods dict to JSON string for JSONB column
        route_dict['methods'] = json.dumps(route_dict['methods'])

        with self.get_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO routes (route_id, route_pattern, service_name, methods, created_at, updated_at)
                VALUES (%(route_id)s, %(route_pattern)s, %(service_name)s, %(methods)s, %(created_at)s, %(updated_at)s)
                ON CONFLICT (route_id)
                DO UPDATE SET
                    route_pattern = EXCLUDED.route_pattern,
                    service_name = EXCLUDED.service_name,
                    methods = EXCLUDED.methods,
                    updated_at = EXCLUDED.updated_at
                """,
                route_dict
            )

    def delete_route(self, route_id: str) -> bool:
        """
        Delete a route by its ID.

        Args:
            route_id: Route identifier

        Returns:
            True if route was deleted, False if not found
        """
        with self.get_cursor() as cursor:
            cursor.execute(
                "DELETE FROM routes WHERE route_id = %s",
                (route_id,)
            )
            return cursor.rowcount > 0

    def close(self) -> None:
        """Close all connections in the pool."""
        if self.pool and not self.pool.closed:
            self.pool.closeall()

    def __del__(self):
        """Cleanup connection pool on deletion."""
        if hasattr(self, 'pool'):
            self.close()
