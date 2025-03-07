from auth_server.server_client import ServerClient
from fastapi import Request, Response
from auth_types import (
    StartInteractiveLoginOptions,
    LogoutOptions
)

from stores.cookie_transaction_store import CookieTransactionStore
from stores.stateless_state_store import StatelessStateStore

from config import Auth0Config

class AuthClient:
    """
    FastAPI SDK client that wraps auth0-server-python functionality.
    It configures the underlying client with the proper state and transaction stores,
    and exposes helper methods for starting login, completing the login callback,
    logging out, and handling backchannel logout.
    """
    def __init__(self, config: Auth0Config, state_store=None, transaction_store=None):
        self.config = config
        # Build the redirect URI based on the provided app_base_url
        redirect_uri =  f"{str(config.app_base_url).rstrip('/')}/auth/callback"
        
        # Use provided state_store or default to an in-memory implementation
        if state_store is None:
            state_store = StatelessStateStore(config.secret, cookie_name="auth0_session", expiration=config.session_expiration)
        # Use provided transaction_store or default to an cookie implementation
        if transaction_store is None:
            transaction_store = CookieTransactionStore(config.secret, cookie_name="auth0_tx")
        
        self.client = ServerClient(
            domain=config.domain,
            client_id=config.client_id,
            client_secret=config.client_secret,
            redirect_uri=redirect_uri,
            secret=config.secret,
            transaction_store=transaction_store,
            state_store=state_store,
            state_absolute_duration=config.session_expiration,
            authorization_params={
                "audience": config.audience,
                "redirect_uri": redirect_uri,
            },
        )
    
    async def start_login(self, request: Request, app_state: dict = None, store_options: dict = None) -> str:
        """
        Initiates the interactive login process.
        Optionally, an app_state dictionary can be passed to persist additional state.
        Returns the authorization URL to redirect the user.
        """
        options = StartInteractiveLoginOptions(app_state=app_state)
        return await self.client.start_interactive_login(options, request=request, store_options=store_options)
    
    async def complete_login(self, request: Request, callback_url: str, store_options: dict = None) -> dict:
        """
        Completes the interactive login process using the callback URL.
        Returns a dictionary with the session state data.
        """
        return await self.client.complete_interactive_login(callback_url, request, store_options=store_options)
    
    async def logout(self, return_to: str = None, store_options: dict = None ) -> str:
        """
        Initiates logout by clearing the session and generating a logout URL.
        Optionally accepts a return_to URL for redirection after logout.
        """
        options = LogoutOptions(return_to=return_to)
        return await self.client.logout(options, store_options=store_options)
    
    async def handle_backchannel_logout(self, logout_token: str) -> None:
        """
        Processes a backchannel logout using the provided logout token.
        """
        return await self.client.handle_backchannel_logout(logout_token)
