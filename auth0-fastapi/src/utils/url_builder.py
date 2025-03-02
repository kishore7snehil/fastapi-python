from __future__ import annotations
from typing import Any, Dict
import json
from urllib.parse import urlencode


class URLBuilder:
    """
    Handles construction of Auth0 authorization URLs and PAR requests.
    Maintains original URL building logic from auth_client.py
    """

    def __init__(self, auth_client: Any):
        """
        Initialize URL builder.
        Args:
            auth_client: Parent AIAuth instance
        """
        self.auth_client = auth_client

    def get_logout_url(self, return_to: str) -> str:
        """
        Generate the logout URL.
        Args:
            return_to: The URL to which the user should be redirected after logout.
        Returns:
            A complete logout URL.
        """
        params = {
            "client_id": self.auth_client.client_id,
            "returnTo": return_to
        }
        query_string = urlencode(params)
        return f"https://{self.auth_client.domain}/v2/logout?{query_string}"

    def get_authorize_par_url(self, state: str, request_uri: str) -> str:
        """
        Generate PAR authorization URL.
        Args:
            state: State parameter for CSRF protection
            request_uri: PAR request URI
        Returns:
            Complete PAR authorization URL
        """
        params = {
            "client_id": self.auth_client.client_id,
            "state": state,
            "request_uri": request_uri
        }
        query_string = urlencode(params)
        return f"https://{self.auth_client.domain}/authorize?{query_string}"

