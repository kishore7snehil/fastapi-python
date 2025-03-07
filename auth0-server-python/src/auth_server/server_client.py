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

from authlib.integrations.starlette_client import OAuth, OAuthError
from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from pydantic import BaseModel, ValidationError
from starlette.requests import Request
from starlette.responses import RedirectResponse

from error import (
    MissingTransactionError, 
    ApiError, 
    MissingRequiredArgumentError,
    BackchannelLogoutError,
    AccessTokenError,
    AccessTokenErrorCode
)
from auth_types import (
    StateData, 
    TransactionData, 
    UserClaims, 
    TokenSet,
    LogoutTokenClaims,
    ServerClientOptionsWithSecret,
    StartInteractiveLoginOptions,
    LoginBackchannelOptions,
    LogoutOptions
)
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
        self._oauth = OAuth()
        self._oauth.register(
            name="auth0",
            server_metadata_url=f"https://{domain}/.well-known/openid-configuration",
            client_id=client_id,
            client_secret=client_secret,
            client_kwargs={
                "scope": "openid profile email",
                "token_endpoint_auth_method": "client_secret_post"
            }
        )
    
    async def start_interactive_login(
        self, 
        options: Optional[StartInteractiveLoginOptions] = None
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
        code_verifier = self._generate_code_verifier()
        code_challenge = self._generate_code_challenge(code_verifier)
        
        # Add PKCE parameters to the authorization request
        auth_params["code_challenge"] = code_challenge
        auth_params["code_challenge_method"] = "S256"
        
        # State parameter to prevent CSRF
        state = self._generate_random_string(32)
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
            True
        )
        
        # Generate the authorization URL
        auth_client = self._oauth.create_client("auth0")
        auth_url = auth_client.authorize_redirect(None, **auth_params)
        
        return auth_url
    
    async def complete_interactive_login(
        self, 
        url: str, 
        store_options: Optional[Dict[str, Any]] = None
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
        transaction_data = await self._transaction_store.get(transaction_identifier, store_options)
        
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
            auth_client = self._oauth.create_client("auth0")
            token_response = await auth_client.fetch_token(
                code=code,
                code_verifier=transaction_data.code_verifier
            )
        except OAuthError as e:
            raise ApiError("token_error", str(e), e)
        
        # Parse and validate the ID token
        id_token = token_response.get("id_token")
        claims = None
        if id_token:
            claims = jwt.decode(id_token, options={"verify_signature": False})
            # In a production implementation, we should verify the token signature
            # and validate claims like audience, issuer, etc.
        
        # Extract user information
        user_claims = None
        if claims:
            user_claims = UserClaims.parse_obj(claims)
        
        # Build state data to store
        sid = claims.get("sid") if claims else self._generate_random_string(32)
        
        state_data = StateData(
            user=user_claims,
            id_token=id_token,
            refresh_token=token_response.get("refresh_token"),
            token_sets=[
                TokenSet(
                    audience=token_response.get("audience", "default"),
                    access_token=token_response.get("access_token", ""),
                    scope=token_response.get("scope", ""),
                    expires_at=int(time.time()) + token_response.get("expires_in", 3600)
                )
            ],
            internal={
                "sid": sid,
                "created_at": int(time.time())
            }
        )
        
        # Store the state data
        await self._state_store.set(
            self._state_identifier, 
            state_data,
            True, 
            store_options
        )
        
        # Clean up transaction data
        await self._transaction_store.delete(transaction_identifier, store_options)
        
        # Return the result with app state if provided
        result = {
            "state_data": state_data.dict(),
        }
        
        if transaction_data.app_state:
            result["app_state"] = transaction_data.app_state
            
        return result
    
    async def logout(
        self, 
        options: Optional[LogoutOptions] = None,
        store_options: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Logs the user out and returns a URL to redirect to.
        
        Args:
            options: Configuration options for the logout process
            store_options: Options to pass to the state store
            
        Returns:
            Logout URL to redirect the user to
        """
        options = options or LogoutOptions()
        
        # Delete the session from the state store
        await self._state_store.delete(self._state_identifier, store_options)
        
        # Build the logout URL
        base_url = f"https://{self._domain}/v2/logout"
        params = {
            "client_id": self._client_id,
        }
        
        if options.return_to:
            params["returnTo"] = options.return_to
            
        # Convert params to query string
        query_string = "&".join([f"{k}={v}" for k, v in params.items()])
        logout_url = f"{base_url}?{query_string}"
        
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
    
    async def get_user_info(
        self, 
        store_options: Optional[Dict[str, Any]] = None
    ) -> Optional[UserClaims]:
        """
        Gets the current user information from the session.
        
        Args:
            store_options: Options to pass to the state store
            
        Returns:
            User claims or None if no session exists
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        if not state_data or not state_data.user:
            return None
        
        return state_data.user
    
    async def get_access_token(
        self, 
        audience: Optional[str] = None,
        scope: Optional[str] = None,
        store_options: Optional[Dict[str, Any]] = None
    ) -> Optional[str]:
        """
        Gets an access token for the specified audience and scope.
        
        Args:
            audience: The API audience for the token
            scope: The requested scope
            store_options: Options to pass to the state store
            
        Returns:
            Access token or None if no matching token exists
        """
        state_data = await self._state_store.get(self._state_identifier, store_options)
        if not state_data:
            raise AccessTokenError(AccessTokenErrorCode.MISSING_SESSION, "No session found")
        
        # Default audience if not specified
        audience = audience or "default"
        
        # Look for an existing token that matches the criteria
        for token_set in state_data.token_sets:
            if token_set.audience == audience:
                # Check if token is expired
                if token_set.expires_at <= int(time.time()):
                    # Need to refresh the token
                    if not state_data.refresh_token:
                        raise AccessTokenError(
                            AccessTokenErrorCode.MISSING_REFRESH_TOKEN, 
                            "No refresh token available"
                        )
                    
                    # Refresh the token (implementation would go here)
                    # For now, we'll just raise an error
                    raise AccessTokenError(
                        AccessTokenErrorCode.FAILED_TO_REFRESH_TOKEN,
                        "Token refresh not implemented in this example"
                    )
                
                # Token is valid, return it
                return token_set.access_token
        
        # No matching token found, try to get a new one if we have a refresh token
        if not state_data.refresh_token:
            raise AccessTokenError(
                AccessTokenErrorCode.MISSING_REFRESH_TOKEN,
                "No refresh token available"
            )
        
        # Request a new token (implementation would go here)
        # For now, we'll just raise an error
        raise AccessTokenError(
            AccessTokenErrorCode.FAILED_TO_REQUEST_TOKEN,
            "Requesting new tokens not implemented in this example"
        )
