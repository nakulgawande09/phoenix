from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, Mock, patch

import pytest


class TestAzureTokenProvider:
    """Tests for AzureTokenProvider class."""

    def test_lazy_credential_initialization(self) -> None:
        """Test that DefaultAzureCredential is lazily initialized."""
        from phoenix.db.azure_auth import AzureTokenProvider

        provider = AzureTokenProvider()
        assert provider._credential is None

    def test_import_error_when_azure_identity_not_installed(self) -> None:
        """Test ImportError is raised when azure-identity is not installed."""
        from phoenix.db.azure_auth import AzureTokenProvider

        provider = AzureTokenProvider()

        with patch.dict("sys.modules", {"azure.identity": None}):
            with patch(
                "phoenix.db.azure_auth.AzureTokenProvider._get_credential",
                side_effect=ImportError("azure-identity is required for Azure AD authentication."),
            ):
                with pytest.raises(ImportError, match="azure-identity"):
                    provider.get_token_sync()

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_get_token_sync_obtains_token(self, mock_credential_class: MagicMock) -> None:
        """Test that get_token_sync obtains a token from Azure."""
        from phoenix.db.azure_auth import AZURE_POSTGRES_SCOPE, AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "test-azure-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        provider = AzureTokenProvider()
        token = provider.get_token_sync()

        assert token == "test-azure-token"
        mock_credential.get_token.assert_called_once_with(AZURE_POSTGRES_SCOPE)

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_get_token_sync_caches_token(self, mock_credential_class: MagicMock) -> None:
        """Test that tokens are cached and not fetched again if valid."""
        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "cached-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        provider = AzureTokenProvider()

        token1 = provider.get_token_sync()
        token2 = provider.get_token_sync()

        assert token1 == token2 == "cached-token"
        # Should only call get_token once due to caching
        assert mock_credential.get_token.call_count == 1

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_token_refresh_when_expired(self, mock_credential_class: MagicMock) -> None:
        """Test that token is refreshed when expired within margin."""
        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_credential_class.return_value = mock_credential

        # First token expires soon (within margin)
        mock_token1 = Mock()
        mock_token1.token = "first-token"
        mock_token1.expires_on = (datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()

        # Second token is valid
        mock_token2 = Mock()
        mock_token2.token = "second-token"
        mock_token2.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()

        mock_credential.get_token.side_effect = [mock_token1, mock_token2]

        provider = AzureTokenProvider(refresh_margin_seconds=600)

        # First call gets first token
        token1 = provider.get_token_sync()
        assert token1 == "first-token"

        # Second call should refresh because token expires within margin
        token2 = provider.get_token_sync()
        assert token2 == "second-token"

        assert mock_credential.get_token.call_count == 2

    def test_token_validity_check_no_token(self) -> None:
        """Test _is_token_valid returns False when no token exists."""
        from phoenix.db.azure_auth import AzureTokenProvider

        provider = AzureTokenProvider()
        assert not provider._is_token_valid()

    def test_token_validity_check_valid_token(self) -> None:
        """Test _is_token_valid returns True for valid token."""
        from phoenix.db.azure_auth import AzureTokenProvider

        provider = AzureTokenProvider(refresh_margin_seconds=600)
        provider._token = "test-token"
        provider._expires_on = datetime.now(timezone.utc) + timedelta(minutes=30)

        assert provider._is_token_valid()

    def test_token_validity_check_expired_within_margin(self) -> None:
        """Test _is_token_valid returns False when token expires within margin."""
        from phoenix.db.azure_auth import AzureTokenProvider

        provider = AzureTokenProvider(refresh_margin_seconds=600)
        provider._token = "test-token"
        provider._expires_on = datetime.now(timezone.utc) + timedelta(minutes=5)

        # Token expires in 5 minutes, but margin is 10 minutes, so it's invalid
        assert not provider._is_token_valid()

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_managed_identity_client_id_passed(self, mock_credential_class: MagicMock) -> None:
        """Test that managed_identity_client_id is passed to DefaultAzureCredential."""
        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "mi-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        provider = AzureTokenProvider(managed_identity_client_id="test-client-id")
        provider.get_token_sync()

        mock_credential_class.assert_called_once_with(managed_identity_client_id="test-client-id")

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_managed_identity_from_env_var(self, mock_credential_class: MagicMock) -> None:
        """Test that client ID is read from PHOENIX_AZURE_CLIENT_ID env var."""
        import os

        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "env-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        with patch.dict(os.environ, {"PHOENIX_AZURE_CLIENT_ID": "env-client-id"}):
            provider = AzureTokenProvider()
            provider.get_token_sync()

            mock_credential_class.assert_called_once_with(
                managed_identity_client_id="env-client-id"
            )

    @pytest.mark.asyncio
    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    async def test_get_token_async(self, mock_credential_class: MagicMock) -> None:
        """Test async token retrieval."""
        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "async-test-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        provider = AzureTokenProvider()
        token = await provider.get_token_async()

        assert token == "async-test-token"

    @pytest.mark.asyncio
    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    async def test_get_token_async_uses_cache(self, mock_credential_class: MagicMock) -> None:
        """Test that async token retrieval uses cache."""
        from phoenix.db.azure_auth import AzureTokenProvider

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "cached-async-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        provider = AzureTokenProvider()

        # First call populates cache
        token1 = await provider.get_token_async()
        # Second call should use cache
        token2 = await provider.get_token_async()

        assert token1 == token2 == "cached-async-token"
        assert mock_credential.get_token.call_count == 1


class TestGlobalSingletons:
    """Tests for global singleton functions."""

    def test_get_azure_postgres_token_provider_returns_singleton(self) -> None:
        """Test that get_azure_postgres_token_provider returns the same instance."""
        import phoenix.db.azure_auth
        from phoenix.db.azure_auth import (
            AZURE_POSTGRES_SCOPE,
            get_azure_postgres_token_provider,
        )

        # Reset global state for test
        phoenix.db.azure_auth._azure_postgres_token_provider = None

        provider1 = get_azure_postgres_token_provider()
        provider2 = get_azure_postgres_token_provider()

        assert provider1 is provider2
        assert provider1._scope == AZURE_POSTGRES_SCOPE

    def test_get_azure_sql_token_provider_returns_singleton(self) -> None:
        """Test that get_azure_sql_token_provider returns the same instance."""
        import phoenix.db.azure_auth
        from phoenix.db.azure_auth import (
            AZURE_SQL_SCOPE,
            get_azure_sql_token_provider,
        )

        # Reset global state for test
        phoenix.db.azure_auth._azure_sql_token_provider = None

        provider1 = get_azure_sql_token_provider()
        provider2 = get_azure_sql_token_provider()

        assert provider1 is provider2
        assert provider1._scope == AZURE_SQL_SCOPE

    @patch("phoenix.db.azure_auth.DefaultAzureCredential", autospec=True)
    def test_generate_azure_postgres_token(self, mock_credential_class: MagicMock) -> None:
        """Test the simple generate_azure_postgres_token function."""
        from phoenix.db.azure_auth import generate_azure_postgres_token

        mock_credential = Mock()
        mock_token = Mock()
        mock_token.token = "generated-token"
        mock_token.expires_on = (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        mock_credential.get_token.return_value = mock_token
        mock_credential_class.return_value = mock_credential

        # Reset global state
        import phoenix.db.azure_auth

        phoenix.db.azure_auth._azure_postgres_token_provider = None

        token = generate_azure_postgres_token()

        assert token == "generated-token"


class TestConfigValidation:
    """Tests for Azure AD configuration validation in config.py."""

    def test_mutual_exclusivity_aws_azure_connection_str(self, monkeypatch: Any) -> None:
        """Test that AWS IAM and Azure AD auth cannot both be enabled in connection string."""
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AWS_IAM_AUTH", "true")
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AZURE_AD_AUTH", "true")
        monkeypatch.setenv("PHOENIX_POSTGRES_HOST", "test.postgres.database.azure.com")
        monkeypatch.setenv("PHOENIX_POSTGRES_USER", "testuser")

        # Need to reload the module to pick up environment changes
        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        with pytest.raises(ValueError, match="Cannot enable both"):
            phoenix.config.get_env_postgres_connection_str()

    def test_password_not_allowed_with_azure_ad(self, monkeypatch: Any) -> None:
        """Test that password is rejected when Azure AD is enabled."""
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AZURE_AD_AUTH", "true")
        monkeypatch.setenv("PHOENIX_POSTGRES_HOST", "test.postgres.database.azure.com")
        monkeypatch.setenv("PHOENIX_POSTGRES_USER", "testuser")
        monkeypatch.setenv("PHOENIX_POSTGRES_PASSWORD", "should-not-be-set")
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AWS_IAM_AUTH", "false")

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        with pytest.raises(ValueError, match="will be ignored"):
            phoenix.config.get_env_postgres_connection_str()

    def test_azure_ad_connection_string_no_password(self, monkeypatch: Any) -> None:
        """Test that Azure AD builds connection string without password."""
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AZURE_AD_AUTH", "true")
        monkeypatch.setenv("PHOENIX_POSTGRES_HOST", "test.postgres.database.azure.com")
        monkeypatch.setenv("PHOENIX_POSTGRES_USER", "admin@test")
        monkeypatch.setenv("PHOENIX_POSTGRES_DB", "phoenix")
        monkeypatch.setenv("PHOENIX_POSTGRES_PORT", "5432")
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AWS_IAM_AUTH", "false")
        # Ensure password is not set
        monkeypatch.delenv("PHOENIX_POSTGRES_PASSWORD", raising=False)

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        conn_str = phoenix.config.get_env_postgres_connection_str()

        assert conn_str is not None
        assert "admin%40test" in conn_str  # URL-encoded @
        assert "test.postgres.database.azure.com" in conn_str
        assert "phoenix" in conn_str
        assert "5432" in conn_str
        # No password in URL
        assert ":password@" not in conn_str.lower()

    def test_get_env_postgres_use_azure_ad_auth_default_false(self, monkeypatch: Any) -> None:
        """Test that Azure AD auth defaults to False."""
        monkeypatch.delenv("PHOENIX_POSTGRES_USE_AZURE_AD_AUTH", raising=False)

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_postgres_use_azure_ad_auth() is False

    def test_get_env_postgres_use_azure_ad_auth_true(self, monkeypatch: Any) -> None:
        """Test that Azure AD auth can be enabled."""
        monkeypatch.setenv("PHOENIX_POSTGRES_USE_AZURE_AD_AUTH", "true")

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_postgres_use_azure_ad_auth() is True

    def test_get_env_postgres_azure_ad_token_lifetime_default(self, monkeypatch: Any) -> None:
        """Test that Azure AD token lifetime defaults to 3000 seconds."""
        monkeypatch.delenv("PHOENIX_POSTGRES_AZURE_AD_TOKEN_LIFETIME_SECONDS", raising=False)

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_postgres_azure_ad_token_lifetime() == 3000

    def test_get_env_postgres_azure_ad_token_lifetime_custom(self, monkeypatch: Any) -> None:
        """Test that Azure AD token lifetime can be customized."""
        monkeypatch.setenv("PHOENIX_POSTGRES_AZURE_AD_TOKEN_LIFETIME_SECONDS", "2400")

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_postgres_azure_ad_token_lifetime() == 2400

    def test_get_env_postgres_azure_ad_token_lifetime_invalid(self, monkeypatch: Any) -> None:
        """Test that invalid token lifetime raises error."""
        monkeypatch.setenv("PHOENIX_POSTGRES_AZURE_AD_TOKEN_LIFETIME_SECONDS", "0")

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        with pytest.raises(ValueError, match="must be a positive integer"):
            phoenix.config.get_env_postgres_azure_ad_token_lifetime()

    def test_get_env_azure_client_id(self, monkeypatch: Any) -> None:
        """Test that Azure client ID is read from environment."""
        monkeypatch.setenv("PHOENIX_AZURE_CLIENT_ID", "test-client-id-123")

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_azure_client_id() == "test-client-id-123"

    def test_get_env_azure_client_id_not_set(self, monkeypatch: Any) -> None:
        """Test that Azure client ID returns None when not set."""
        monkeypatch.delenv("PHOENIX_AZURE_CLIENT_ID", raising=False)

        import importlib

        import phoenix.config

        importlib.reload(phoenix.config)

        assert phoenix.config.get_env_azure_client_id() is None
