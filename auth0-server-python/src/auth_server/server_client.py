"""
Main client for auth0-server-python SDK.
Handles authentication flows, token management, and user sessions.
"""

import time
import secrets
import string
from typing import Dict, Any, Optional, List, Union, TypeVar, Generic, Callable
from urllib.parse import urlparse, parse_qs
import base64
import hashlib
import json
from datetime import datetime, timedelta

from authlib.integrations.httpx_client import AsyncOAuth2Client
from authlib.integrations.base_client.errors import OAuthError
import httpx 
from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import RedirectResponse
from fastapi import Request, Response

from error import (
    MissingTransactionError, 
    ApiError, 
    MissingRequiredArgumentError,
    BackchannelLogoutError,
    AccessTokenError,
    AccessTokenForConnectionError,
    AccessTokenErrorCode,
    AccessTokenForConnectionErrorCode
    
)
from auth_types import (
    StateData, 
    TransactionData, 
    UserClaims, 
    TokenSet,
    LogoutTokenClaims,
    StartInteractiveLoginOptions,
    LoginBackchannelOptions,
    AccessTokenForConnectionOptions,
    LogoutOptions
)
from utils import PKCE, State, URL
from store.memory import MemoryStateStore, MemoryTransactionStore

# Generic type for store options
TStoreOptions = TypeVar('TStoreOptions')

class ServerClient(Generic[TStoreOptions]):
    """
    Main client for Auth0 server SDK. Handles authentication flows, session management,
    and token operations using Authlib for OIDC functionality.
    """
    
    def __init__(
        self,
        domain: str,
        client_id: str,
        client_secret: str,
        redirect_uri: Optional[str] = None,
        secret: str = None,
        transaction_store = None,
        state_store = None,
        state_absolute_duration: int = 259200,  # 3 days in seconds
        transaction_identifier: str = "_a0_tx",
        state_identifier: str = "_a0_session",
        authorization_params: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the Auth0 server client.
        
        Args:
            domain: Auth0 domain (e.g., 'your-tenant.auth0.com')
            client_id: Auth0 client ID
            client_secret: Auth0 client secret
            redirect_uri: Default redirect URI for authentication
            secret: Secret used for encryption
            transaction_store: Custom transaction store (defaults to MemoryTransactionStore)
            state_store: Custom state store (defaults to MemoryStateStore)
            state_absolute_duration: Time in seconds before state expires (default: 3 days)
            transaction_identifier: Identifier for transaction data
            state_identifier: Identifier for state data
            authorization_params: Default parameters for authorization requests
        """
        if not secret:
            raise MissingRequiredArgumentError("secret")
            
        # Store configuration
        self._domain = domain
        self._client_id = client_id
        self._client_secret = client_secret
        self._redirect_uri = redirect_uri
        self._default_authorization_params = authorization_params or {}
        
        # Initialize stores
        self._transaction_store = transaction_store or MemoryTransactionStore(secret)
        self._state_store = state_store or MemoryStateStore(secret, state_absolute_duration)
        self._transaction_identifier = transaction_identifier
        self._state_identifier = state_identifier
        
        # Initialize OAuth client
        self._oauth = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
        )

    async def _fetch_oidc_metadata(self, domain: str) -> dict:
        metadata_url = f"https://{domain}/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            response = await client.get(metadata_url)
            response.raise_for_status()
            return response.json()

    
    async def start_interactive_login(
        self,
        options: Optional[StartInteractiveLoginOptions] = None,
        request: Request = None,
        store_options: dict = None
    ) -> str:
        """
        Starts the interactive login process and returns a URL to redirect to.
        
        Args:
            options: Configuration options for the login process
            
        Returns:
            Authorization URL to redirect the user to
        """
        options = options or StartInteractiveLoginOptions()
        
        # Get effective authorization params (merge defaults with provided ones)
        auth_params = dict(self._default_authorization_params)
        if options.authorization_params:
            auth_params.update(options.authorization_params)
            
        # Ensure we have a redirect_uri
        if "redirect_uri" not in auth_params and not self._redirect_uri:
            raise MissingRequiredArgumentError("redirect_uri")
        
        # Use the default redirect_uri if none is specified
        if "redirect_uri" not in auth_params and self._redirect_uri:
            auth_params["redirect_uri"] = self._redirect_uri
        
        # Generate PKCE code verifier and challenge
        code_verifier = PKCE.generate_code_verifier()
        code_challenge = PKCE.generate_code_challenge(code_verifier)
        
        # Add PKCE parameters to the authorization request
        auth_params["code_challenge"] = code_challenge
        auth_params["code_challenge_method"] = "S256"
        
        # State parameter to prevent CSRF
        state = PKCE.generate_random_string(32)
        auth_params["state"] = state
        
        # Build the transaction data to store
        transaction_data = TransactionData(
            code_verifier=code_verifier,
            app_state=options.app_state
        )

        # Store the transaction data
        await self._transaction_store.set(
            f"{self._transaction_identifier}:{state}", 
            transaction_data,
            options=store_options
        )

        # Generate the authorization URL
        try:
            self._oauth.metadata = await self._fetch_oidc_metadata(self._domain)
        except Exception as e:
            raise ApiError("metadata_error", "Failed to fetch OIDC metadata", e)

        if "authorization_endpoint" not in self._oauth.metadata:
            raise ApiError("configuration_error", "Authorization endpoint missing in OIDC metadata")

        authorization_endpoint = self._oauth.metadata["authorization_endpoint"]

        try:
            auth_url, state = self._oauth.create_authorization_url(authorization_endpoint, **auth_params)
        except Exception as e:
            raise ApiError("authorization_url_error", "Failed to create authorization URL", e)

        return auth_url
    
    async def complete_interactive_login(
        self, 
        url: str,
        request: Request = None,  
        store_options: dict = None
    ) -> Dict[str, Any]:
        """
        Completes the login process after user is redirected back.
        
        Args:
            url: The full callback URL including query parameters
            store_options: Options to pass to the state store
            
        Returns:
            Dictionary containing session data and app state
        """
        # Parse the URL to get query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        
        # Get state parameter from the URL
        state = query_params.get("state", [""])[0]
        if not state:
            raise MissingRequiredArgumentError("state")
        
        # Retrieve the transaction data using the state
        transaction_identifier = f"{self._transaction_identifier}:{state}"
        transaction_data = await self._transaction_store.get(transaction_identifier, options=store_options)
        
        if not transaction_data:
            raise MissingTransactionError()
        
        # Check for error response from Auth0
        if "error" in query_params:
            error = query_params.get("error", [""])[0]
            error_description = query_params.get("error_description", [""])[0]
            raise ApiError(error, error_description)
        
        # Get the authorization code from the URL
        code = query_params.get("code", [""])[0]
        if not code:
            raise MissingRequiredArgumentError("code")
        
        # Exchange the code for tokens
        try:
            token_endpoint = self._oauth.metadata["token_endpoint"]
            token_response = await self._oauth.fetch_token(
                token_endpoint,
                code=code,
                code_verifier=transaction_data.code_verifier,
                redirect_uri=self._redirect_uri,
            )
        except OAuthError as e:
            # Raise a custom error (or handle it as appropriate)
            raise ApiError("token_error", f"Token exchange failed: {str(e)}", e)
        
       # Use the userinfo field from the token_response for user claims
        user_info = token_response.get("userinfo")
        user_claims = None
        if user_info:
            user_claims = UserClaims.parse_obj(user_info)
        else:
            # Alternatively, decode id_token if needed (not recommended if userinfo is available)
            id_token = token_response.get("id_token")
            if id_token:
                # Note: For production, properly verify the token
                user_claims = UserClaims.parse_obj(jwt.decode(id_token, key=None, claims_options={"verify_signature": False}))
        
        # Build a token set using the token response data
        token_set = TokenSet(
            audience=token_response.get("audience", "default"),
            access_token=token_response.get("access_token", ""),
            scope=token_response.get("scope", ""),
            expires_at=int(time.time()) + token_response.get("expires_in", 3600)
        )
        
        # Generate a session id (sid) from token_response or transaction data, or create a new one
        sid = user_info.get("sid") if user_info and "sid" in user_info else PKCE.generate_random_string(32)
        
        # Construct state data to represent the session
        state_data = StateData(
            user=user_claims,
            id_token=token_response.get("id_token"),
            refresh_token=token_response.get("refresh_token"),  # might be None if not provided
            token_sets=[token_set],
            internal={
                "sid": sid,
                "created_at": int(time.time())
            }
        )
        
        # Store the state data in the state store using store_options (Response required)
        await self._state_store.set(self._state_identifier, state_data, options=store_options)
        
        # Clean up transaction data after successful login
        await self._transaction_store.delete(transaction_identifier, options=store_options)
        
        result = {"state_data": state_data.dict()}
        if transaction_data.app_state:
            result["app_state"] = transaction_data.app_state
            
        return result    

    
    async def login_backchannel(
        self,
        options: LoginBackchannelOptions,
        store_options: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Logs in using Client-Initiated Backchannel Authentication.
        
        Note:
            Using Client-Initiated Backchannel Authentication requires the feature 
            to be enabled in the Auth0 dashboard.
        
        See:
            https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-initiated-backchannel-authentication-flow
        
        Args:
            options: Options used to configure the backchannel login process.
            store_options: Optional options used to pass to the Transaction and State Store.
            
        Returns:
            A dictionary containing the authorizationDetails (when RAR was used).
        """
        token_endpoint_response = await self._auth_client.backchannel_authentication({
            "binding_message": options.binding_message,
            "login_hint": options.login_hint,
            "authorization_params": options.authorization_params,
        })
        
        existing_state_data = await self._state_store.get(self._state_identifier, store_options)
        
        audience = getattr(self._options.get("authorization_params", {}), "audience", "default")
        state_data = State.update_state_data(
            audience,
            existing_state_data,
            token_endpoint_response
        )
        
        await self._state_store.set(self._state_identifier, state_data, True, store_options)
        
        return {
            "authorization_details": token_endpoint_response.get("authorization_details")
        }

    async def get_user(self, store_options: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves the user from the store, or None if no user found.
        
        Args:
            store_options: Optional options used to pass to the Transaction and State Store.
            
        Returns:
            The user, or None if no user found in the store.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        
        if state_data:
            return state_data.get("user")
        
        return None

    async def get_session(self, store_options: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieve the user session from the store, or None if no session found.
        
        Args:
            store_options: Optional options used to pass to the Transaction and State Store.
            
        Returns:
            The session, or None if no session found in the store.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        
        if state_data:
            # Create a copy and remove internal data
            session_data = {k: v for k, v in state_data.items() if k != "internal"}
            return session_data
        
        return None

    async def get_access_token(self, store_options: Optional[Dict[str, Any]] = None) -> str:
        """
        Retrieves the access token from the store, or calls Auth0 when the access token 
        is expired and a refresh token is available in the store.
        Also updates the store when a new token was retrieved from Auth0.
        
        Args:
            store_options: Optional options used to pass to the Transaction and State Store.
            
        Returns:
            The access token, retrieved from the store or Auth0.
            
        Raises:
            AccessTokenError: If the token is expired and no refresh token is available.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        
        # Get audience and scope from options or use defaults
        auth_params = getattr(self._options, "authorization_params", {}) or {}
        audience = auth_params.get("audience", "default")
        scope = auth_params.get("scope")
        
        # Find matching token set
        token_set = None
        if state_data and state_data.get("token_sets"):
            for ts in state_data["token_sets"]:
                if ts.get("audience") == audience and (not scope or ts.get("scope") == scope):
                    token_set = ts
                    break
        
        # If token is valid, return it
        if token_set and token_set.get("expires_at", 0) > time.time():
            return token_set["access_token"]
        
        # Check for refresh token
        if not state_data or not state_data.get("refresh_token"):
            raise AccessTokenError(
                AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
                "The access token has expired and a refresh token was not provided. The user needs to re-authenticate."
            )
        
        # Get new token with refresh token
        token_endpoint_response = await self._auth_client.get_token_by_refresh_token({
            "refresh_token": state_data["refresh_token"]
        })
        
        # Update state data with new token
        existing_state_data = await self._state_store.get(self._state_identifier, store_options)
        updated_state_data = State.update_state_data(audience, existing_state_data, token_endpoint_response)
        
        # Store updated state
        await self._state_store.set(self._state_identifier, updated_state_data, False, store_options)
        
        return token_endpoint_response["access_token"]

    async def get_access_token_for_connection(
        self,
        options: AccessTokenForConnectionOptions,
        store_options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Retrieves an access token for a connection.
        
        This method attempts to obtain an access token for a specified connection.
        It first checks if a refresh token exists in the store.
        If no refresh token is found, it throws an `AccessTokenForConnectionError` indicating
        that the refresh token was not found.
        
        Args:
            options: Options for retrieving an access token for a connection.
            store_options: Optional options used to pass to the Transaction and State Store.
            
        Returns:
            The access token for the connection
            
        Raises:
            AccessTokenForConnectionError: If the access token was not found or 
                there was an issue requesting the access token.
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        
        # Find existing connection token
        connection_token_set = None
        if state_data and state_data.get("connection_token_sets"):
            for ts in state_data["connection_token_sets"]:
                if ts.get("connection") == options.connection:
                    connection_token_set = ts
                    break
        
        # If token is valid, return it
        if connection_token_set and connection_token_set.get("expires_at", 0) > time.time():
            return connection_token_set["access_token"]
        
        # Check for refresh token
        if not state_data or not state_data.get("refresh_token"):
            raise AccessTokenForConnectionError(
                AccessTokenForConnectionErrorCode.MISSING_REFRESH_TOKEN,
                "A refresh token was not found but is required to be able to retrieve an access token for a connection."
            )
        
        # Get new token for connection
        token_endpoint_response = await self._auth_client.get_token_for_connection({
            "connection": options.connection,
            "login_hint": options.login_hint,
            "refresh_token": state_data["refresh_token"]
        })
        
        # Update state data with new token
        updated_state_data = State.update_state_data_for_connection_token_set(options, state_data, token_endpoint_response)
        
        # Store updated state
        await self._state_store.set(self._state_identifier, updated_state_data, False, store_options)
        
        return token_endpoint_response["access_token"]
    

    async def logout(
        self, 
        options: Optional[LogoutOptions] = None,
        store_options: Optional[Dict[str, Any]] = None
    ) -> str:
        options = options or LogoutOptions()
        
        # Delete the session from the state store
        await self._state_store.delete(self._state_identifier, store_options)
        
        # Use the URL helper to create the logout URL.
        logout_url = URL.create_logout_url(self._domain, self._client_id, options.return_to)
        
        return logout_url
    
    async def handle_backchannel_logout(
        self, 
        logout_token: str, 
        store_options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Handles backchannel logout requests.
        
        Args:
            logout_token: The logout token sent by Auth0
            store_options: Options to pass to the state store
        """
        if not logout_token:
            raise BackchannelLogoutError("Missing logout token")
        
        try:
            # Decode the token without verification (for demonstration)
            # In production, you should verify the token signature
            claims = jwt.decode(logout_token, options={"verify_signature": False})
            
            # Validate the token is a logout token
            events = claims.get("events", {})
            if "http://schemas.openid.net/event/backchannel-logout" not in events:
                raise BackchannelLogoutError("Invalid logout token: not a backchannel logout event")
            
            # Delete sessions associated with this token
            logout_claims = LogoutTokenClaims(
                sub=claims.get("sub"),
                sid=claims.get("sid")
            )
            
            await self._state_store.delete_by_logout_token(logout_claims.dict(), store_options)
            
        except (jwt.JoseError, ValidationError) as e:
            raise BackchannelLogoutError(f"Error processing logout token: {str(e)}")
    

