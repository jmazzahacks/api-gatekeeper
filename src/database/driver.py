"""
Database driver for API Authentication Service.
Provides connection pooling and database operations for routes, clients, and permissions.
"""
from typing import Optional, List
from contextlib import contextmanager
import json
import psycopg2
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor

from ..models.route import Route
from ..models.client import Client
from ..models.client_permission import ClientPermission
from ..models.rate_limit import RateLimit
from ..monitoring import DB_CONNECTION_POOL


class AuthServiceDB:
    """Database driver for API authentication service with connection pooling."""

    def __init__(
        self,
        db_host: str,
        db_name: str,
        db_user: str,
        db_password: str,
        db_port: int = 5432,
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
            db_port: PostgreSQL port (default: 5432)
            min_conn: Minimum number of connections in pool
            max_conn: Maximum number of connections in pool
        """
        self.pool = ThreadedConnectionPool(
            min_conn,
            max_conn,
            host=db_host,
            port=db_port,
            database=db_name,
            user=db_user,
            password=db_password
        )
        self._active_connections = 0
        self._max_conn = max_conn

        # Initialize pool metrics
        DB_CONNECTION_POOL.labels(state='active').set(0)
        DB_CONNECTION_POOL.labels(state='idle').set(min_conn)
        DB_CONNECTION_POOL.labels(state='max').set(max_conn)

    @contextmanager
    def _get_connection(self):
        """Context manager for getting a connection from the pool."""
        conn = self.pool.getconn()
        self._active_connections += 1
        DB_CONNECTION_POOL.labels(state='active').set(self._active_connections)
        DB_CONNECTION_POOL.labels(state='idle').set(self._max_conn - self._active_connections)
        try:
            yield conn
        finally:
            self.pool.putconn(conn)
            self._active_connections -= 1
            DB_CONNECTION_POOL.labels(state='active').set(self._active_connections)
            DB_CONNECTION_POOL.labels(state='idle').set(self._max_conn - self._active_connections)

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

    def find_matching_routes(self, path: str, domain: Optional[str] = None) -> List[Route]:
        """
        Find all routes that match a given path and domain (exact or wildcard).

        Args:
            path: URL path to match
            domain: Domain to match (optional, case-insensitive)

        Returns:
            List of matching Route objects, sorted by specificity:
            - Exact domain + exact path (highest priority)
            - Exact domain + wildcard path
            - Wildcard domain + exact path
            - Wildcard domain + wildcard path
            - Any domain (*) + exact path
            - Any domain (*) + wildcard path (lowest priority)
        """
        routes = self.load_all_routes()

        # Filter routes that match both path and domain
        matching_routes = [
            route for route in routes
            if route.matches(path) and route.matches_domain(domain)
        ]

        # Sort by specificity (most specific first)
        def route_specificity(route: Route) -> tuple:
            # Domain specificity: exact (0) > wildcard subdomain (1) > any (*) (2)
            if route.domain.lower() == (domain.lower() if domain else ''):
                domain_score = 0  # Exact match
            elif route.domain.startswith('*.'):
                domain_score = 1  # Wildcard subdomain
            else:  # route.domain == '*'
                domain_score = 2  # Any domain

            # Path specificity: exact (0) > wildcard (1)
            path_score = 1 if route.route_pattern.endswith('/*') else 0

            # Return tuple for sorting (lower is more specific)
            return (domain_score, path_score)

        matching_routes.sort(key=route_specificity)
        return matching_routes

    def save_route(self, route: Route) -> str:
        """
        Insert or update a route in the database.

        Args:
            route: Route object to save

        Returns:
            The route_id (either provided or auto-generated by database)
        """
        route_dict = route.to_dict()
        # Convert methods dict to JSON string for JSONB column
        route_dict['methods'] = json.dumps(route_dict['methods'])

        with self.get_cursor() as cursor:
            if route.route_id:
                # Update existing route
                cursor.execute(
                    """
                    INSERT INTO routes (route_id, route_pattern, domain, service_name, methods, created_at, updated_at)
                    VALUES (%(route_id)s, %(route_pattern)s, %(domain)s, %(service_name)s, %(methods)s, %(created_at)s, %(updated_at)s)
                    ON CONFLICT (route_id)
                    DO UPDATE SET
                        route_pattern = EXCLUDED.route_pattern,
                        domain = EXCLUDED.domain,
                        service_name = EXCLUDED.service_name,
                        methods = EXCLUDED.methods,
                        updated_at = EXCLUDED.updated_at
                    RETURNING route_id
                    """,
                    route_dict
                )
            else:
                # Insert new route without route_id (let database generate UUID)
                # Remove route_id from dict since it's None
                insert_dict = {k: v for k, v in route_dict.items() if k != 'route_id'}
                cursor.execute(
                    """
                    INSERT INTO routes (route_pattern, domain, service_name, methods, created_at, updated_at)
                    VALUES (%(route_pattern)s, %(domain)s, %(service_name)s, %(methods)s, %(created_at)s, %(updated_at)s)
                    RETURNING route_id
                    """,
                    insert_dict
                )

            result = cursor.fetchone()
            route_id = str(result[0])
            # Update the route object with the generated ID
            route.route_id = route_id
            return route_id

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

    # ========== Client Operations ==========

    def load_client_by_id(self, client_id: str) -> Optional[Client]:
        """
        Load a client by its ID.

        Args:
            client_id: Client identifier

        Returns:
            Client object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM clients WHERE client_id = %s",
                (client_id,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return Client.from_dict(dict(result))

    def load_client_by_api_key(self, api_key: str) -> Optional[Client]:
        """
        Load a client by its API key.

        Args:
            api_key: Client's API key

        Returns:
            Client object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM clients WHERE api_key = %s",
                (api_key,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return Client.from_dict(dict(result))

    def load_client_by_shared_secret(self, shared_secret: str) -> Optional[Client]:
        """
        Load a client by its shared secret.

        Args:
            shared_secret: Client's shared secret

        Returns:
            Client object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM clients WHERE shared_secret = %s",
                (shared_secret,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return Client.from_dict(dict(result))

    def load_all_clients(self) -> List[Client]:
        """
        Load all clients from the database.

        Returns:
            List of all Client objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM clients ORDER BY client_name")
            results = cursor.fetchall()
            return [Client.from_dict(dict(row)) for row in results]

    def save_client(self, client: Client) -> str:
        """
        Insert or update a client in the database.

        Args:
            client: Client object to save

        Returns:
            The client_id (either provided or auto-generated by database)
        """
        client_dict = client.to_dict()

        with self.get_cursor() as cursor:
            if client.client_id:
                # Update existing client
                cursor.execute(
                    """
                    INSERT INTO clients (client_id, client_name, shared_secret, api_key, status, created_at, updated_at)
                    VALUES (%(client_id)s, %(client_name)s, %(shared_secret)s, %(api_key)s, %(status)s, %(created_at)s, %(updated_at)s)
                    ON CONFLICT (client_id)
                    DO UPDATE SET
                        client_name = EXCLUDED.client_name,
                        shared_secret = EXCLUDED.shared_secret,
                        api_key = EXCLUDED.api_key,
                        status = EXCLUDED.status,
                        updated_at = EXCLUDED.updated_at
                    RETURNING client_id
                    """,
                    client_dict
                )
            else:
                # Insert new client without client_id (let database generate UUID)
                insert_dict = {k: v for k, v in client_dict.items() if k != 'client_id'}
                cursor.execute(
                    """
                    INSERT INTO clients (client_name, shared_secret, api_key, status, created_at, updated_at)
                    VALUES (%(client_name)s, %(shared_secret)s, %(api_key)s, %(status)s, %(created_at)s, %(updated_at)s)
                    RETURNING client_id
                    """,
                    insert_dict
                )

            result = cursor.fetchone()
            client_id = str(result[0])
            # Update the client object with the generated ID
            client.client_id = client_id
            return client_id

    def delete_client(self, client_id: str) -> bool:
        """
        Delete a client by its ID.
        Note: This will cascade delete all associated permissions.

        Args:
            client_id: Client identifier

        Returns:
            True if client was deleted, False if not found
        """
        with self.get_cursor() as cursor:
            cursor.execute(
                "DELETE FROM clients WHERE client_id = %s",
                (client_id,)
            )
            return cursor.rowcount > 0

    # ========== Client Permission Operations ==========

    def load_permission_by_id(self, permission_id: str) -> Optional[ClientPermission]:
        """
        Load a permission by its ID.

        Args:
            permission_id: Permission identifier

        Returns:
            ClientPermission object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM client_permissions WHERE permission_id = %s",
                (permission_id,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return ClientPermission.from_dict(dict(result))

    def load_permissions_by_client(self, client_id: str) -> List[ClientPermission]:
        """
        Load all permissions for a specific client.

        Args:
            client_id: Client identifier

        Returns:
            List of ClientPermission objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM client_permissions WHERE client_id = %s",
                (client_id,)
            )
            results = cursor.fetchall()
            return [ClientPermission.from_dict(dict(row)) for row in results]

    def load_permissions_by_route(self, route_id: str) -> List[ClientPermission]:
        """
        Load all permissions for a specific route.

        Args:
            route_id: Route identifier

        Returns:
            List of ClientPermission objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM client_permissions WHERE route_id = %s",
                (route_id,)
            )
            results = cursor.fetchall()
            return [ClientPermission.from_dict(dict(row)) for row in results]

    def load_permission_by_client_and_route(
        self, client_id: str, route_id: str
    ) -> Optional[ClientPermission]:
        """
        Load a specific permission for a client and route.

        Args:
            client_id: Client identifier
            route_id: Route identifier

        Returns:
            ClientPermission object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM client_permissions WHERE client_id = %s AND route_id = %s",
                (client_id, route_id)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return ClientPermission.from_dict(dict(result))

    def save_permission(self, permission: ClientPermission) -> str:
        """
        Insert or update a permission in the database.

        Args:
            permission: ClientPermission object to save

        Returns:
            The permission_id (either provided or auto-generated by database)
        """
        perm_dict = permission.to_dict()

        with self.get_cursor() as cursor:
            if permission.permission_id:
                # Update existing permission
                cursor.execute(
                    """
                    INSERT INTO client_permissions (permission_id, client_id, route_id, allowed_methods, created_at)
                    VALUES (%(permission_id)s, %(client_id)s, %(route_id)s, %(allowed_methods)s, %(created_at)s)
                    ON CONFLICT (permission_id)
                    DO UPDATE SET
                        allowed_methods = EXCLUDED.allowed_methods
                    RETURNING permission_id
                    """,
                    perm_dict
                )
            else:
                # Insert new permission without permission_id (let database generate UUID)
                insert_dict = {k: v for k, v in perm_dict.items() if k != 'permission_id'}
                cursor.execute(
                    """
                    INSERT INTO client_permissions (client_id, route_id, allowed_methods, created_at)
                    VALUES (%(client_id)s, %(route_id)s, %(allowed_methods)s, %(created_at)s)
                    ON CONFLICT (client_id, route_id)
                    DO UPDATE SET
                        allowed_methods = EXCLUDED.allowed_methods
                    RETURNING permission_id
                    """,
                    insert_dict
                )

            result = cursor.fetchone()
            permission_id = str(result[0])
            # Update the permission object with the generated ID
            permission.permission_id = permission_id
            return permission_id

    def delete_permission(self, permission_id: str) -> bool:
        """
        Delete a permission by its ID.

        Args:
            permission_id: Permission identifier

        Returns:
            True if permission was deleted, False if not found
        """
        with self.get_cursor() as cursor:
            cursor.execute(
                "DELETE FROM client_permissions WHERE permission_id = %s",
                (permission_id,)
            )
            return cursor.rowcount > 0

    def delete_permission_by_client_and_route(
        self, client_id: str, route_id: str
    ) -> bool:
        """
        Delete a permission by client and route IDs.

        Args:
            client_id: Client identifier
            route_id: Route identifier

        Returns:
            True if permission was deleted, False if not found
        """
        with self.get_cursor() as cursor:
            cursor.execute(
                "DELETE FROM client_permissions WHERE client_id = %s AND route_id = %s",
                (client_id, route_id)
            )
            return cursor.rowcount > 0

    # ========== Rate Limit Operations ==========

    def load_rate_limit_by_client(self, client_id: str) -> Optional[RateLimit]:
        """
        Load the rate limit configuration for a client.

        Args:
            client_id: Client identifier

        Returns:
            RateLimit object if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM rate_limits WHERE client_id = %s",
                (client_id,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return RateLimit.from_dict(dict(result))

    def load_all_rate_limits(self) -> List[RateLimit]:
        """
        Load all rate limit configurations.

        Returns:
            List of all RateLimit objects
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM rate_limits ORDER BY client_id")
            results = cursor.fetchall()
            return [RateLimit.from_dict(dict(row)) for row in results]

    def save_rate_limit(self, rate_limit: RateLimit) -> str:
        """
        Insert or update a rate limit configuration.

        Args:
            rate_limit: RateLimit object to save

        Returns:
            The client_id
        """
        rate_limit_dict = rate_limit.to_dict()

        with self.get_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO rate_limits (client_id, requests_per_day, created_at, updated_at)
                VALUES (%(client_id)s, %(requests_per_day)s, %(created_at)s, %(updated_at)s)
                ON CONFLICT (client_id)
                DO UPDATE SET
                    requests_per_day = EXCLUDED.requests_per_day,
                    updated_at = EXCLUDED.updated_at
                RETURNING client_id
                """,
                rate_limit_dict
            )
            result = cursor.fetchone()
            return str(result[0])

    def delete_rate_limit(self, client_id: str) -> bool:
        """
        Delete a rate limit configuration for a client.

        Args:
            client_id: Client identifier

        Returns:
            True if rate limit was deleted, False if not found
        """
        with self.get_cursor() as cursor:
            cursor.execute(
                "DELETE FROM rate_limits WHERE client_id = %s",
                (client_id,)
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
