"""
Main client for auth0-fastapi.
Provides integration between Auth0 and FastAPI applications.
"""
# import os
# import sys
# # Dynamically add `src` folder to sys.path
# current_dir = os.path.dirname(os.path.abspath(__file__))
# sdk_src_path = os.path.abspath(os.path.join(current_dir, '../auth0-server-python/src'))
# sys.path.insert(0, sdk_src_path)
import time
from typing import Optional, Dict, Any, Callable, TypeVar, List, Union, cast
from functools import wraps

from fastapi import FastAPI, Request, Response, Depends, HTTPException
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from auth_server.server_client import ServerClient
from auth_types import StateData, TransactionData

from type import Auth0Options, SessionOptions, UserProfile, LoginOptions, LogoutOptions
from stores import StatelessSessionStore, StatefulSessionStore, CookieTransactionStore
from stores.stateful import MemorySessionBackend
from error import Auth0Error, ConfigurationError, StoreOptionsError
from utils import get_store_options, generate_random_string

# Type for route handler functions
T = TypeVar('T', bound=Callable)


class Auth0Middleware(BaseHTTPMiddleware):
    """Middleware that adds request/response context for auth0-fastapi."""
    
    def __init__(self, app, auth0_client):
        super().__init__(app)
        self.auth0_client = auth0_client
    
    async def dispatch(self, request: Request, call_next):
        """Process a request and add auth0 client to request state."""
        # Create a response object that will be used by the stores
        response = Response()
        
        # Add auth0 client and response to request state
        request.state.auth0 = self.auth0_client
        request.state.auth0_response = response
        
        # Call the next middleware/route handler
        result = await call_next(request)
        
        # Check if there are any cookies to set
        if hasattr(response, "raw_cookies") and response.raw_cookies:
            for cookie in response.raw_cookies:
                result.set_cookie(**cookie)
        
        return result


class Auth0:
    """
    Auth0 integration for FastAPI applications.
    
    Provides authentication, session management, and route protection.
    """
    
    def __init__(
        self,
        app: Optional[FastAPI] = None,
        domain: str = None,
        client_id: str = None,
        client_secret: str = None,
        redirect_uri: Optional[str] = None,
        app_base_url: Optional[str] = None,
        audience: Optional[str] = None,
        scope: str = "openid profile email",
        secret: str = None,
        session_type: str = "cookie",
        session_cookie_name: str = "_a0_session",
        session_cookie_secure: Optional[bool] = None,
        session_cookie_same_site: str = "lax",
        session_duration: int = 259200,  # 3 days
        session_backend: Optional[Any] = None,
        transaction_cookie_name: str = "_a0_tx",
        routes_prefix: str = "/auth",
        mount_routes: bool = True,
        **kwargs
    ):
        """Initialize Auth0 integration with FastAPI."""
        # Store configuration
        self.options = Auth0Options(
            domain=domain,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            app_base_url=app_base_url,
            audience=audience,
            scope=scope,
            secret=secret,
            session=SessionOptions(
                session_type=session_type,
                cookie_name=session_cookie_name,
                cookie_secure=session_cookie_secure,
                cookie_same_site=session_cookie_same_site,
                session_duration=session_duration,
                backend=session_backend,
            ),
            transaction_cookie_name=transaction_cookie_name,
            routes_prefix=routes_prefix,
            mount_routes=mount_routes,
            **kwargs
        )
        
        # Validate configuration
        if not secret:
            raise ConfigurationError("Secret is required for secure session management")
        
        if session_type == "custom" and not session_backend:
            raise ConfigurationError("Custom session backend is required when session_type is 'custom'")
        
        # Set up transaction store
        
        self.transaction_store = CookieTransactionStore(
            secret=secret,
            cookie_name=transaction_cookie_name
        )
        
        # Set up session store based on configuration
        if session_type == "cookie":
            self.session_store = StatelessSessionStore(
                secret=secret,
                cookie_name=session_cookie_name,
                secure=session_cookie_secure,
                same_site=session_cookie_same_site,
                duration=session_duration
            )
        elif session_type == "memory":
            backend = MemorySessionBackend()
            self.session_store = StatefulSessionStore(
                secret=secret,
                backend=backend,
                cookie_name=session_cookie_name,
                secure=session_cookie_secure,
                same_site=session_cookie_same_site,
                duration=session_duration
            )
        elif session_type == "custom":
            self.session_store = StatefulSessionStore(
                secret=secret,
                backend=session_backend,
                cookie_name=session_cookie_name,
                secure=session_cookie_secure,
                same_site=session_cookie_same_site,
                duration=session_duration
            )
        
        # Initialize the core server client from auth0-server-python
        self.server_client = ServerClient(
            domain=domain,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=self._get_callback_url(),
            secret=secret,
            transaction_store=self.transaction_store,
            state_store=self.session_store
        )
        
        # Set up the FastAPI app if provided
        if app:
            self.setup(app)
    
    def setup(self, app: FastAPI) -> None:
        """Set up Auth0 with the FastAPI app."""
        # Add middleware to provide request/response context
        app.add_middleware(Auth0Middleware, auth0_client=self)
        
        # Mount routes if requested
        if self.options.mount_routes:
            prefix = self.options.routes_prefix
            
            app.add_route(f"{prefix}{self.options.login_path}", self.login_route, methods=["GET"])
            app.add_route(f"{prefix}{self.options.callback_path}", self.callback_route, methods=["GET"])
            app.add_route(f"{prefix}{self.options.logout_path}", self.logout_route, methods=["GET"])
            app.add_route(f"{prefix}{self.options.backchannel_logout_path}", self.backchannel_logout_route, methods=["POST"])
    
    # Route handlers
    
    async def login_route(self, request: Request) -> RedirectResponse:
        """Handle login requests."""
        # Get return_to from query parameters
        return_to = request.query_params.get("returnTo", "/")
        
        # Get other login options
        audience = request.query_params.get("audience", self.options.audience)
        scope = request.query_params.get("scope", self.options.scope)
        
        # Create store options with request/response context
        store_options = get_store_options(request)
        
        try:
            # Generate state parameter for CSRF protection
            state = generate_random_string(32)
            
            # Create transaction data
            transaction_data = {
                "state": state,
                "app_state": {"returnTo": return_to}
            }
            
            # Store transaction data
            transaction_id = f"{self.options.transaction_cookie_name}:{state}"
            await self.transaction_store.set(transaction_id, transaction_data, False, store_options)
            
            # Create authorization parameters
            auth_params = {
                "response_type": "code",
                "redirect_uri": self._get_callback_url(),
                "state": state
            }
            
            if audience:
                auth_params["audience"] = audience
                
            if scope:
                auth_params["scope"] = scope
            
            # Get Auth0 client
            auth_client = self.oauth.create_client("auth0")
            
            # Create authorization URL
            redirect_uri = auth_client.authorize_redirect(request, **auth_params)
            
            return redirect_uri
        except Exception as e:
            # Log error
            print(f"Error starting login: {str(e)}")
            raise HTTPException(status_code=500, detail="Error starting authentication process")
    
    async def callback_route(self, request: Request) -> RedirectResponse:
        """Handle callback from Auth0."""
        # Create store options with request/response context
        store_options = get_store_options(request)
        
        try:
            # Use the core server client to complete login
            result = await self.server_client.complete_interactive_login(
                str(request.url), 
                store_options
            )
            
            # Get return URL from app state
            return_to = "/"
            if result.get("app_state") and result["app_state"].get("returnTo"):
                return_to = result["app_state"]["returnTo"]
            
            return RedirectResponse(url=return_to, status_code=302)
        except Auth0Error as e:
            # Redirect to login with error
            print(f"Auth error: {str(e)}")
            return RedirectResponse(
                url=f"{self.options.routes_prefix}{self.options.login_path}?error={str(e)}",
                status_code=302
            )
        except Exception as e:
            # Log error
            print(f"Callback error: {str(e)}")
            raise HTTPException(status_code=500, detail="Error completing authentication")
    
    async def logout_route(self, request: Request) -> RedirectResponse:
        """Handle logout requests."""
        # Get return_to from query parameters
        return_to = request.query_params.get("returnTo")
        if not return_to and self.options.app_base_url:
            return_to = self.options.app_base_url
        
        # Create logout options
        logout_options = {}
        if return_to:
            logout_options["return_to"] = return_to
        
        # Create store options with request/response context
        store_options = get_store_options(request)
        
        try:
            # Use the core server client to handle logout
            logout_url = await self.server_client.logout(
                logout_options, 
                store_options
            )
            
            return RedirectResponse(url=logout_url, status_code=302)
        except Exception as e:
            # Log error
            print(f"Logout error: {str(e)}")
            raise HTTPException(status_code=500, detail="Error during logout")
    
    async def backchannel_logout_route(self, request: Request) -> Response:
        """Handle backchannel logout requests."""
        try:
            # Get logout token from form data
            form_data = await request.form()
            logout_token = form_data.get("logout_token")
            
            if not logout_token:
                return Response(content="Missing logout_token in the request body", status_code=400)
            
            # Create store options with request/response context
            store_options = get_store_options(request)
            
            # Use the core server client to handle backchannel logout
            await self.server_client.handle_backchannel_logout(
                logout_token, 
                store_options
            )
            
            return Response(status_code=204)
        except Auth0Error as e:
            return Response(content=str(e), status_code=400)
        except Exception as e:
            # Log error
            print(f"Backchannel logout error: {str(e)}")
            return Response(content=str(e), status_code=500)
    
    # Utility methods
    
    def requires_auth(self, f: T = None) -> T:
        """Decorator to protect routes, requiring authentication."""
        def decorator(func):
            @wraps(func)
            async def wrapper(request: Request, *args, **kwargs):
                user = await self.get_user(request)
                if not user:
                    return_to = str(request.url)
                    login_url = f"{self.options.routes_prefix}{self.options.login_path}?returnTo={return_to}"
                    return RedirectResponse(url=login_url, status_code=302)
                return await func(request, *args, **kwargs)
            return wrapper
        
        # Allow use as either @requires_auth or @requires_auth()
        if f:
            return decorator(f)
        return decorator
    
    async def get_user(self, request: Request) -> Optional[UserProfile]:
        """Get the authenticated user for the current request."""
        # Create store options with request/response context
        store_options = get_store_options(request)
        
        try:
            # Get session data using our session store
            session_data = await self.session_store.get(
                self.options.session.cookie_name,
                store_options
            )
            
            if not session_data or not session_data.get("user"):
                return None
            
            # Convert to UserProfile model
            return UserProfile(**session_data["user"])
        except Exception as e:
            # Log error
            print(f"Error getting user: {str(e)}")
            return None
    
    async def get_access_token(self, request: Request) -> Optional[str]:
        """Get the access token for the current session."""
        # Create store options with request/response context
        store_options = get_store_options(request)
        
        try:
            # Get session data using our session store
            session_data = await self.session_store.get(
                self.options.session.cookie_name,
                store_options
            )
            
            if not session_data:
                return None
            
            # Check if token is expired
            expires_at = session_data.get("expires_at", 0)
            if expires_at < time.time():
                # Token is expired
                return None
            
            return session_data.get("access_token")
        except Exception as e:
            # Log error
            print(f"Error getting access token: {str(e)}")
            return None
    
    # Helper methods
    
    def _get_callback_url(self) -> str:
        """Get the callback URL for OAuth redirects."""
        if self.options.redirect_uri:
            return self.options.redirect_uri
        
        if not self.options.app_base_url:
            raise ConfigurationError("Either redirect_uri or app_base_url must be provided")
        
        return f"{self.options.app_base_url.rstrip('/')}{self.options.routes_prefix}{self.options.callback_path}"


# Convenience functions for FastAPI dependency injection

def get_user(request: Request) -> Optional[UserProfile]:
    """FastAPI dependency to get the current user."""
    auth0 = getattr(request.state, "auth0", None)
    if not auth0:
        raise RuntimeError("Auth0 client not properly initialized. Make sure to use Auth0 middleware.")
    
    return auth0.get_user(request)


def get_access_token(request: Request) -> Optional[str]:
    """FastAPI dependency to get the current access token."""
    auth0 = getattr(request.state, "auth0", None)
    if not auth0:
        raise RuntimeError("Auth0 client not properly initialized. Make sure to use Auth0 middleware.")
    
    return auth0.get_access_token(request)


def requires_auth(request: Request):
    """FastAPI dependency to require authentication."""
    auth0 = getattr(request.state, "auth0", None)
    if not auth0:
        raise RuntimeError("Auth0 client not properly initialized. Make sure to use Auth0 middleware.")
    
    user = auth0.get_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    return user