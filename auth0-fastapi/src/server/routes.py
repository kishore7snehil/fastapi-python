from __future__ import annotations
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse

from authlib.integrations.starlette_client import OAuthError
import jwt
import time



def setup_routes(app, auth_client: Any) -> None:
    """Set up all routes for the authentication server."""

    @app.get("/auth/callback")
    async def callback_handler(request: Request, response: Response):
        """Handle OAuth callback with Authlib integration."""

        # Delegate the entire flow (exchange token + store session) to AuthClient
        login_response = await auth_client.completeInteractiveLogin(request, response)

        # Return success
        return {"message": "Login successful", "user": login_response.user}
      
        
    @app.get("/auth/login")
    async def login(request: Request, response: Response):

        return await auth_client.oauth.auth0.authorize_redirect(request, auth_client.redirect_uri, scope="openid profile email offline_access", access_type="offline", prompt="consent", grant_type="authorization_code", response_type="code")
    
    @app.get("/auth/profile")
    async def profile(request: Request, response: Response):

        user = await auth_client.getUser(request, response)
        return JSONResponse({"user": user})
    
    @app.get("/auth/logout")
    async def logout(request: Request, response:Response):
        """
        Logs out the user locally and then redirects them to Auth0's logout endpoint,
        using a developer-specified `returnTo` if provided in query params.
        """
        logoutUrl = await auth_client.logout(request, response)

        return RedirectResponse(url=logoutUrl)