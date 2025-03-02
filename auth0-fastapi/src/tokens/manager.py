from __future__ import annotations
from typing import Any, Dict,Optional
from authlib.integrations.starlette_client import OAuthError


class TokenManager:
    """
    Manages token operations, including exchange, refresh, and validation.
    """
    def __init__(self, auth_client):
        """
        :param auth_client: An instance of your Auth class 
                            that already has self.oauth.auth0 set up.
        """
        self.auth_client = auth_client

    async def get_access_token_for_connection(
        self,
        connection: str,
        refresh_token: str,
    ) -> dict:
        """
        Fetch an access token for a specified federated connection
        using a refresh token and Auth0's custom grant type.

        :param connection: e.g. "github", "google-oauth2", etc.
        :param refresh_token: The user's refresh token (already obtained)
        :param login_hint: (Optional) If you'd like to provide a login hint.
        
        :returns: The token response from Auth0 (including access_token, expires_in, etc.)
        """

        # Arguments for the fetch_token call
        fetch_token_kwargs = {
            "url": f"https://{self.auth_client.domain}/oauth/token",
            "grant_type": "urn:ietf:params:oauth:grant-type:federated-connection:access_token",
            "connection": connection,
            "subject_token": refresh_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:refresh_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:federated-connection:access_token",
        }

        try:
            # Authlib's fetch_token method
            token_response = await self.auth_client.oauth.auth0.fetch_token(**fetch_token_kwargs)
            return token_response
        except OAuthError as e:
            raise e