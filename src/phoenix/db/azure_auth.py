from __future__ import annotations

import asyncio
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# Azure resource scopes for database authentication
AZURE_POSTGRES_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"
AZURE_SQL_SCOPE = "https://database.windows.net/.default"

# Default refresh margin (10 minutes before expiry)
DEFAULT_REFRESH_MARGIN_SECONDS = 600


class AzureTokenProvider:
    """
    Thread-safe token provider with background refresh for Azure AD authentication.

    Azure AD tokens for PostgreSQL are valid for approximately 60 minutes.
    This class maintains a cached token and refreshes it in the background
    before expiry to ensure uninterrupted database access.

    The provider uses DefaultAzureCredential which supports multiple authentication
    methods in the following order:
    1. Environment variables (service principal)
    2. Workload Identity (Kubernetes)
    3. Managed Identity (Azure VMs, App Service, etc.)
    4. Azure CLI
    5. Azure PowerShell
    6. Azure Developer CLI
    """

    def __init__(
        self,
        scope: str = AZURE_POSTGRES_SCOPE,
        managed_identity_client_id: Optional[str] = None,
        refresh_margin_seconds: int = DEFAULT_REFRESH_MARGIN_SECONDS,
    ) -> None:
        """
        Initialize the Azure token provider.

        Args:
            scope: Azure resource scope for token acquisition.
                   Use AZURE_POSTGRES_SCOPE for Azure Database for PostgreSQL.
                   Use AZURE_SQL_SCOPE for Azure SQL Database.
            managed_identity_client_id: Optional client ID for user-assigned managed identity.
                                       If not provided, reads from PHOENIX_AZURE_CLIENT_ID env var.
                                       If neither is set, DefaultAzureCredential will use
                                       system-assigned managed identity or other credentials.
            refresh_margin_seconds: Refresh tokens this many seconds before expiry (default: 600).
        """
        self._scope = scope
        self._client_id = managed_identity_client_id or os.getenv("PHOENIX_AZURE_CLIENT_ID")
        self._refresh_margin = timedelta(seconds=refresh_margin_seconds)
        self._token: Optional[str] = None
        self._expires_on: Optional[datetime] = None
        self._lock = threading.Lock()
        self._credential: Optional[object] = None  # Lazy initialization
        self._refresh_task: Optional[asyncio.Task[None]] = None
        self._running = False

    def _get_credential(self) -> object:
        """
        Lazy initialization of DefaultAzureCredential.

        Returns:
            DefaultAzureCredential instance configured for the specified identity.

        Raises:
            ImportError: If azure-identity is not installed.
        """
        if self._credential is None:
            try:
                from azure.identity import DefaultAzureCredential
            except ImportError as e:
                raise ImportError(
                    "azure-identity is required for Azure AD authentication. "
                    "Install it with: pip install 'arize-phoenix[container]'"
                ) from e

            # Pass managed_identity_client_id if configured (for user-assigned MI)
            if self._client_id:
                logger.debug(
                    f"Initializing DefaultAzureCredential with managed_identity_client_id: "
                    f"{self._client_id[:8]}..."
                )
                self._credential = DefaultAzureCredential(
                    managed_identity_client_id=self._client_id
                )
            else:
                logger.debug(
                    "Initializing DefaultAzureCredential without explicit client ID "
                    "(will use system-assigned MI or other credentials)"
                )
                self._credential = DefaultAzureCredential()

        return self._credential

    def _is_token_valid(self) -> bool:
        """
        Check if the cached token is still valid (with refresh margin).

        Returns:
            True if the token exists and won't expire within the refresh margin.
        """
        if self._token is None or self._expires_on is None:
            return False
        return datetime.now(timezone.utc) + self._refresh_margin < self._expires_on

    def get_token_sync(self) -> str:
        """
        Synchronously get a valid Azure AD token for database authentication.

        This method is thread-safe and will refresh the token if needed.
        Use this for synchronous database operations (e.g., psycopg migrations).

        Returns:
            A valid Azure AD JWT token to use as the database password.

        Raises:
            ImportError: If azure-identity is not installed.
            Exception: If Azure credentials are not configured or token generation fails.
        """
        with self._lock:
            if self._is_token_valid():
                return self._token  # type: ignore[return-value]

            credential = self._get_credential()
            try:
                token = credential.get_token(self._scope)  # type: ignore[union-attr]
                self._token = token.token
                self._expires_on = datetime.fromtimestamp(token.expires_on, tz=timezone.utc)

                logger.debug(
                    f"Obtained Azure AD token for scope {self._scope}, "
                    f"expires at {self._expires_on.isoformat()}"
                )
                return self._token

            except Exception as e:
                logger.error(
                    f"Failed to obtain Azure AD token for database authentication: {e}. "
                    "Ensure Azure credentials are configured via environment variables, "
                    "managed identity, or Azure CLI."
                )
                raise

    async def get_token_async(self) -> str:
        """
        Asynchronously get a valid Azure AD token for database authentication.

        This method checks the cache first and uses a thread pool for the actual
        credential call to avoid blocking the event loop.
        Use this for async database operations (e.g., asyncpg connections).

        Returns:
            A valid Azure AD JWT token to use as the database password.

        Raises:
            ImportError: If azure-identity is not installed.
            Exception: If Azure credentials are not configured or token generation fails.
        """
        # Check cache first without lock for performance
        if self._is_token_valid():
            return self._token  # type: ignore[return-value]

        # Use thread pool for sync credential call to avoid blocking
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.get_token_sync)

    async def start_background_refresh(self, interval_seconds: int = 3000) -> None:
        """
        Start a background task that proactively refreshes the token.

        The background task will refresh the token periodically to ensure
        a valid token is always available without waiting for on-demand refresh.

        Args:
            interval_seconds: How often to check/refresh the token (default: 3000 = 50 minutes).
        """
        if self._running:
            logger.warning("Background token refresh is already running")
            return

        self._running = True
        self._refresh_task = asyncio.create_task(
            self._background_refresh_loop(interval_seconds),
            name="azure-token-refresh",
        )
        logger.info(f"Started Azure AD background token refresh (interval: {interval_seconds}s)")

    async def stop_background_refresh(self) -> None:
        """Stop the background token refresh task."""
        self._running = False
        if self._refresh_task and not self._refresh_task.done():
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            logger.info("Stopped Azure AD background token refresh")

    async def _background_refresh_loop(self, interval_seconds: int) -> None:
        """
        Background loop that refreshes tokens before expiry.

        Args:
            interval_seconds: Sleep interval between refresh checks.
        """
        while self._running:
            try:
                # Refresh if token is missing or will expire soon
                if not self._is_token_valid():
                    await self.get_token_async()
                    logger.info("Background Azure AD token refresh completed successfully")
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Background Azure AD token refresh failed: {e}")

            try:
                await asyncio.sleep(interval_seconds)
            except asyncio.CancelledError:
                break


# Global singleton instances for token providers
_azure_postgres_token_provider: Optional[AzureTokenProvider] = None
_azure_sql_token_provider: Optional[AzureTokenProvider] = None
_provider_lock = threading.Lock()


def get_azure_postgres_token_provider() -> AzureTokenProvider:
    """
    Get or create the global Azure PostgreSQL token provider singleton.

    Returns:
        AzureTokenProvider configured for Azure Database for PostgreSQL.
    """
    global _azure_postgres_token_provider
    with _provider_lock:
        if _azure_postgres_token_provider is None:
            _azure_postgres_token_provider = AzureTokenProvider(scope=AZURE_POSTGRES_SCOPE)
        return _azure_postgres_token_provider


def get_azure_sql_token_provider() -> AzureTokenProvider:
    """
    Get or create the global Azure SQL Database token provider singleton.

    Returns:
        AzureTokenProvider configured for Azure SQL Database.
    """
    global _azure_sql_token_provider
    with _provider_lock:
        if _azure_sql_token_provider is None:
            _azure_sql_token_provider = AzureTokenProvider(scope=AZURE_SQL_SCOPE)
        return _azure_sql_token_provider


def generate_azure_postgres_token() -> str:
    """
    Generate an Azure AD token for Azure Database for PostgreSQL.

    This function provides a simple interface similar to generate_aws_rds_token
    for cases where background refresh is not needed or for one-off token generation.

    Returns:
        A valid Azure AD JWT token to use as the database password.

    Raises:
        ImportError: If azure-identity is not installed.
        Exception: If Azure credentials are not configured or token generation fails.

    Example:
        >>> token = generate_azure_postgres_token()
        >>> # Use token as password in database connection
    """
    return get_azure_postgres_token_provider().get_token_sync()
