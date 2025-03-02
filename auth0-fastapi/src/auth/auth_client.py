from __future__ import annotations
from typing import Any
import jwt
from typing import Any, Dict, Optional


from authlib.integrations.starlette_client import OAuth
from fastapi import FastAPI, Request, Response, HTTPException
       

from .base import BaseAuth
from tokens import TokenManager
from store.cookie_store import CookieStore
from store.memory_store import MemoryStore
from server.routes import setup_routes
from utils.url_builder import URLBuilder



class Auth(BaseAuth):
    """Main authentication class that orchestrates the auth flow"""

    def __init__(
            self,
            domain: str | None = None,
            client_id: str | None = None,
            client_secret: str | None = None,
            redirect_uri: str | None = None,
            secret_key: str | None = None,
            app_base_url: str | None = None,
            app :  None = None,
            store: None = None,
            *args, **kwargs):
        """Initialize Auth with all necessary components"""
        super().__init__(
            domain=domain,
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=redirect_uri,
            secret_key=secret_key,
            app_base_url=app_base_url,
            *args, **kwargs
        )

        # Initialize components
        self.token_manager = TokenManager(self)
        self.url_builder = URLBuilder(self)
        if store:
            if store=="CookieStore":
                self.store = CookieStore()
            else:
                self.store = MemoryStore()

        # Initialize app
        self.app = app

        # Setup routes 
        setup_routes(self.app,self)

        # Initialize OAuth client with authlib
        self.oauth = OAuth()
        self.oauth.register(
            name="auth0",
            client_id=self.client_id,
            client_secret=self.client_secret,
            server_metadata_url=f"https://{self.domain}/.well-known/openid-configuration",
            authorize_url=f"https://{self.domain}/authorize",
            client_kwargs={
                "redirect_uri": self.redirect_uri
            }
        )


    async def completeInteractiveLogin(self, request: Request, response: Response) -> dict:
        # Authlib handles the callback parsing and token exchange
        token = await self.oauth.auth0.authorize_access_token(request)
        user = token['userinfo']
        if user:
            user_id = user.get("sub") if user else None 
            
            session_data = {
                "user": user,
                "id_token": token.get("id_token"),
                "refresh_token": token.get("refresh_token"),
            }


            if hasattr(self.store, "split_cookie"):
                self.store.set(response, data=session_data)
            else:
                self.store.set("user", session_data)

            response.user = user
            return response
                
        else:
            raise HTTPException(
                status_code=400, detail="No user_id found in token data.")
        
    async def getUser(self, request: Request, response: Response) -> dict:

        if hasattr(self.store, "split_cookie"):
            user_data=self.store.get(request)
            if not user_data:
                raise HTTPException(
                status_code=401, detail="No active session.")
            
        else:
            user_data = self.store.get("user")
        if user_data:
            return user_data["user"]

        else:
            raise HTTPException(
                status_code=400, detail="No user found")
        
    async def logout(self, request: Request, response: Response) -> dict:

        logoutURL = self.url_builder.get_logout_url(self.app_base_url)

        if hasattr(self.store, "split_cookie"):
            user_data=self.store.get(request)
            if not user_data:
                raise HTTPException(
                status_code=401, detail="No active session.")
            self.store.delete(response)
            
        else:
            self.store.delete("user")

        return logoutURL

        
        
    async def accessTokenForConnection(self, connection: str, refresh_token: str) -> dict:
        return await self.token_manager.get_access_token_for_connection(connection, refresh_token)