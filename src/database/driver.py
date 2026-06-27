"""
Database driver for API Authentication Service.
Provides connection pooling and database operations for routes, clients, and permissions.
"""
from typing import Optional, List, Iterator
from contextlib import contextmanager
import json
import logging
import psycopg2
from psycopg2.extensions import connection as PgConnection
from psycopg2.pool import ThreadedConnectionPool
from psycopg2.extras import RealDictCursor

from api_gatekeeper_models import Route, Client, ClientPermission, RateLimit, ConsoleAdmin
from ..monitoring import DB_CONNECTION_POOL


logger = logging.getLogger(__name__)


# Exception classes that MIGHT mean the socket is dead. OperationalError is
# also raised by app-level failures on perfectly healthy conns
# (SerializationFailure, DeadlockDetected, QueryCanceled, LockNotAvailable
# all subclass OperationalError), so membership in this tuple alone is NOT
# enough to decide — `_is_dead_conn_error` checks `conn.closed` to
# disambiguate.
_DEAD_CONN_ERRORS = (psycopg2.OperationalError, psycopg2.InterfaceError)

# How many times to retry checkout when pre-ping fails.
#
# Bounded intentionally low to fail fast when Postgres is genuinely
# down (each attempt pays ~1× connect_timeout). The tradeoff: after a
# Postgres restart with a full pool of dead idle conns, the first
# ~ceil(max_conn / MAX_HEALTH_RETRIES) callers will raise RuntimeError
# while corpses are drained before fresh conns get created. With the
# default max_conn=10 that's roughly the first 4 callers post-restart.
# Acceptable for our request volume; revisit if observed in practice.
MAX_HEALTH_RETRIES = 3


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
            password=db_password,
            # TCP keepalives — let the OS detect a silently dropped conn
            # within ~80s instead of "until next reboot."
            keepalives=1,
            keepalives_idle=30,
            keepalives_interval=10,
            keepalives_count=5,
        )
        self._active_connections = 0
        self._max_conn = max_conn

        # Initialize pool metrics
        DB_CONNECTION_POOL.labels(state='active').set(0)
        DB_CONNECTION_POOL.labels(state='idle').set(min_conn)
        DB_CONNECTION_POOL.labels(state='max').set(max_conn)

    @staticmethod
    def _is_dead_conn_error(conn: Optional[PgConnection], exc: BaseException) -> bool:
        """
        True if `exc` indicates the underlying socket is unusable.

        InterfaceError always means the conn is dead. OperationalError is
        shared between true dead-conn cases and app-level failures on
        healthy conns (SerializationFailure, DeadlockDetected,
        QueryCanceled, LockNotAvailable all subclass OperationalError) —
        psycopg2 sets `conn.closed` to non-zero only when the socket is
        actually broken, so that's the reliable signal. If conn is None
        (e.g., getconn itself raised), assume dead.
        """
        if isinstance(exc, psycopg2.InterfaceError):
            return True
        if isinstance(exc, psycopg2.OperationalError):
            return conn is None or getattr(conn, 'closed', 0) != 0
        return False

    def _record_pool_metrics(self) -> None:
        """Update active/idle pool gauges. Swallows metric backend errors."""
        try:
            DB_CONNECTION_POOL.labels(state='active').set(self._active_connections)
            DB_CONNECTION_POOL.labels(state='idle').set(
                self._max_conn - self._active_connections
            )
        except Exception:
            logger.exception("Failed to update DB pool metrics")

    def _safe_putback(self, conn: Optional[PgConnection], close: bool = False) -> None:
        """
        Return conn to the pool. On putback failure, force-close the conn
        so it doesn't leak. No-op if conn is None.
        """
        if conn is None:
            return
        try:
            self.pool.putconn(conn, close=close)
        except Exception:
            logger.exception("DB pool putconn failed; force-closing conn")
            try:
                conn.close()
            except Exception:
                logger.exception("Force-close of orphaned DB conn also failed")

    @staticmethod
    def _check_alive(conn: PgConnection) -> None:
        """Cheap `SELECT 1` pre-ping. Raises on dead conn."""
        cur = conn.cursor()
        try:
            cur.execute("SELECT 1")
            cur.fetchone()
        finally:
            try:
                cur.close()
            except Exception:
                logger.exception("DB cursor close failed during pre-ping cleanup")
        # Reset transaction state so the caller gets a clean slate.
        conn.rollback()

    def _checkout_healthy(self) -> PgConnection:
        """
        Get a pre-pinged, healthy conn from the pool.

        On dead conn, discards (putconn close=True so pool refills) and
        retries up to MAX_HEALTH_RETRIES times. On retry exhaustion,
        raises RuntimeError chained from the last underlying error.
        Non-dead exceptions during checkout (e.g., PoolError) propagate
        without retry.
        """
        last_err: Optional[BaseException] = None
        for attempt in range(MAX_HEALTH_RETRIES):
            conn: Optional[PgConnection] = None
            try:
                conn = self.pool.getconn()
                self._check_alive(conn)
                return conn
            except _DEAD_CONN_ERRORS as e:
                last_err = e
                self._safe_putback(conn, close=True)
                logger.warning(
                    "DB checkout pre-ping failed (attempt %d/%d): %s",
                    attempt + 1, MAX_HEALTH_RETRIES, e,
                )
                continue
            except BaseException:
                self._safe_putback(conn, close=True)
                raise

        raise RuntimeError(
            f"Could not acquire a healthy DB connection after "
            f"{MAX_HEALTH_RETRIES} attempts"
        ) from last_err

    @contextmanager
    def _get_connection(self) -> Iterator[PgConnection]:
        """
        Yield a healthy pooled connection.

        On exception inside the yielded block, distinguishes between:
          - dead conn (rollback fails OR conn.closed is set) — discard
            with putconn(close=True) so the pool refills
          - app-level error on a healthy conn (SerializationFailure,
            DeadlockDetected, ValueError, etc.) — rollback, recycle the
            conn with plain putconn so pooling is preserved
        """
        conn = self._checkout_healthy()
        self._active_connections += 1
        self._record_pool_metrics()
        try:
            try:
                yield conn
            except BaseException:
                # A successful rollback proves the socket is alive;
                # a failed rollback or `conn.closed` set means it's gone.
                conn_dead = False
                try:
                    conn.rollback()
                except _DEAD_CONN_ERRORS:
                    conn_dead = True
                except Exception:
                    # Rollback failed for an unexpected reason (not in
                    # _DEAD_CONN_ERRORS). Transaction state is now
                    # unknown — possibly with the caller's writes still
                    # pending — so discard with close=True. Without this
                    # arm the conn would leak out of the pool AND the
                    # rollback exception would mask the caller's.
                    # Narrowed to Exception (not BaseException) so
                    # KeyboardInterrupt / SystemExit propagate.
                    logger.exception(
                        "Unexpected DB rollback failure during mid-flight cleanup"
                    )
                    conn_dead = True
                if not conn_dead:
                    conn_dead = getattr(conn, 'closed', 0) != 0
                self._safe_putback(conn, close=conn_dead)
                raise
            else:
                # Symmetric with the exception path: if caller misused the
                # conn handle and closed it directly, discard rather than
                # recycle a corpse.
                self._safe_putback(conn, close=getattr(conn, 'closed', 0) != 0)
        finally:
            self._active_connections -= 1
            self._record_pool_metrics()

    @contextmanager
    def get_cursor(
        self, commit: bool = True, cursor_factory: Optional[type] = None
    ) -> Iterator[psycopg2.extensions.cursor]:
        """
        Context manager for database cursors with automatic commit/rollback.

        Transaction rollback on exception is handled by `_get_connection`;
        this layer is responsible only for the cursor lifecycle and the
        optional commit. cursor.close() in finally is best-effort so the
        caller sees the original exception, not a follow-on cleanup error.

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
            finally:
                try:
                    cursor.close()
                except Exception:
                    logger.exception(
                        "DB cursor close failed in get_cursor cleanup"
                    )

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

    def load_all_permissions(self) -> List[ClientPermission]:
        """
        Load all client permissions from the database.

        Returns:
            List of all ClientPermission objects, ordered by client_id then route_id
            for stable display.
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM client_permissions ORDER BY client_id, route_id"
            )
            results = cursor.fetchall()
            return [ClientPermission.from_dict(dict(row)) for row in results]

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

    def load_all_admins(self) -> List[ConsoleAdmin]:
        """
        Load all console admins from the database.

        Returns:
            List of all ConsoleAdmin objects, ordered by email
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute("SELECT * FROM console_admins ORDER BY email")
            results = cursor.fetchall()
            return [ConsoleAdmin.from_dict(dict(row)) for row in results]

    def get_admin_by_aegis_id(self, aegis_user_id: int) -> Optional[ConsoleAdmin]:
        """
        Look up a console admin by their Aegis user ID.

        Args:
            aegis_user_id: Aegis-side user identifier

        Returns:
            ConsoleAdmin if found, None otherwise
        """
        with self.get_cursor(commit=False, cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                "SELECT * FROM console_admins WHERE aegis_user_id = %s",
                (aegis_user_id,)
            )
            result = cursor.fetchone()
            if not result:
                return None
            return ConsoleAdmin.from_dict(dict(result))

    def create_admin(self, admin: ConsoleAdmin) -> Optional[ConsoleAdmin]:
        """
        Create a console admin, idempotent on aegis_user_id.

        Uses INSERT ... ON CONFLICT DO NOTHING so concurrent webhook deliveries
        for the same Aegis user cannot trip a unique constraint. If the
        aegis_user_id already exists, the existing record is returned.

        Args:
            admin: ConsoleAdmin to persist (admin_id auto-generated if None)

        Returns:
            The created or pre-existing ConsoleAdmin, or None if the INSERT was
            rejected by the email unique constraint (which indicates the email
            is already associated with a different aegis_user_id — a data
            anomaly the caller should surface).
        """
        with self.get_cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                INSERT INTO console_admins (aegis_user_id, email, created_at, updated_at)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                RETURNING *
                """,
                (admin.aegis_user_id, admin.email, admin.created_at, admin.updated_at)
            )
            result = cursor.fetchone()
            if result:
                return ConsoleAdmin.from_dict(dict(result))

            # Conflict: re-read by aegis_user_id. If a record is returned, this
            # was a concurrent/duplicate delivery for the same Aegis user --
            # return it so the caller can respond idempotently. If nothing is
            # returned, the conflict was on the email constraint with a
            # different aegis_user_id (data anomaly) and we surface None.
            cursor.execute(
                "SELECT * FROM console_admins WHERE aegis_user_id = %s",
                (admin.aegis_user_id,)
            )
            existing = cursor.fetchone()
            if existing:
                return ConsoleAdmin.from_dict(dict(existing))
            return None

    def close(self) -> None:
        """Close all connections in the pool."""
        if self.pool and not self.pool.closed:
            self.pool.closeall()

    def __del__(self):
        """Cleanup connection pool on deletion."""
        if hasattr(self, 'pool'):
            self.close()
