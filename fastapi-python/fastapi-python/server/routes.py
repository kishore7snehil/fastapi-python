from __future__ import annotations
from typing import Any

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
import jwt
import time
from auth0.authentication import RevokeToken


def setup_routes(app: FastAPI, auth_client: Any) -> None:
    """Set up all routes for the authentication server."""

    @app.get("/auth/callback")
    async def manage_callback(request: Request, response: Response):
        """Parses and validates callback URL query parameters."""
        query_params = request.query_params
        required_keys = {"code", "state"}

        if query_params.get("error"):
            error_description = query_params.get(
                "error_description", "Unknown error occurred.")
            if query_params.get("state"):
                del auth_client.state_store[query_params.get("state")]
            raise HTTPException(status_code=400, detail=error_description)

        if not required_keys.issubset(query_params.keys()):
            raise HTTPException(
                status_code=400, detail="Missing required query parameters.")

        received_state = query_params["state"]

        # Validate state to prevent CSRF attacks
        if received_state not in auth_client.state_store:
            raise HTTPException(
                status_code=400, detail="Invalid or missing state parameter.")

        # Extract code value from query string
        received_code = query_params["code"]

        auth0_tokens = auth_client.token_manager.exchange_code_for_tokens(
            received_code)

        if auth0_tokens:
            cookie_session_data = await auth_client.session_manager.set_encrypted_session(auth0_tokens, state=received_state)

            # Split the session data into multiple cookies if it exceeds the maximum size
            _set_cookie = await _split_cookie(response, max_size=4096, encoded_data=cookie_session_data, cookie_prefix="__session_data")

            user_id = auth_client.state_store[received_state].get(
                "user_id", "failed")
            return_to = auth_client.state_store[received_state].get(
                "return_to", None)
            auth_client.state_store[received_state] = {
                "user_id": user_id, "is_completed": True}

            if return_to:
                response = RedirectResponse(url=return_to, status_code=302)

            else:
                response.body = b'{"message": "login successful"}'
                response.status_code = 200

            # for some reason, setting the cookie in an outside function does not work!
            for key, value in _set_cookie.items():
                response.set_cookie(
                key=key,
                value=value,
                path="/auth",
                httponly=True,  # Prevent JavaScript access
                # secure=True,  # Send only over HTTPS
                samesite="Lax",  # Protect against CSRF
                )
            
            return response

        else:
            raise HTTPException(
                status_code=400, detail="Failed to exchange code for tokens.")

    @app.get("/auth/login")
    async def manage_login(request: Request, response: Response,
                           return_to: str | None = None, audience: str | None = None, 
                           scope: str | None = None, connection: str | None = None):
        """Handle login initiation."""
        # check cookie for existing session
        auth_cookie = _reconstruct_cookie(request, cookie_prefix="__session_data")
        # auth_cookie = request.cookies.get("__sessionData")
        if auth_cookie:
            decoded_data = jwt.decode(
                auth_cookie, auth_client.secret_key, algorithms=["HS256"])
            # Session cookie exists, do something with it
            # ...
            return RedirectResponse(url="/auth/get_user", status_code=302)
        else:
            # No session cookie, redirect to Auth0
            _scope = scope or "openid profile email"
            _connection = connection or "Username-Password-Authentication"

            state = auth_client._generate_state(return_to=return_to)

            if audience:
                auth_url = auth_client.url_builder.get_authorize_url(
                    state=state, connection=_connection, scope=_scope, audience=audience, return_to=return_to)
            else:
                auth_url = auth_client.url_builder.get_authorize_url(
                    state=state, connection=_connection, scope=_scope)

        return RedirectResponse(url=auth_url, status_code=302)

    @app.get("/auth/get_user")
    async def get_user(request: Request):
        """Reads the session cookie and extracts user info."""
        auth_cookie = _reconstruct_cookie(request, cookie_prefix="__session_data")
        # auth_cookie = request.cookies.get("__sessionData")

        if not auth_cookie:
            raise HTTPException(
                status_code=401, detail="No active session.")

        try:
            # Decode the JWT stored in the session cookie
            decoded_data = jwt.decode(
                auth_cookie, auth_client.secret_key, algorithms=["HS256"])

            # Extract the user ID (sub) from the decoded JWT
            user_id = decoded_data.get("user").get("sub")

            if not user_id:
                raise HTTPException(
                    status_code=400, detail="Invalid session cookie: Missing 'sub' claim.")

            return JSONResponse(content=auth_client.session_manager._get_user_response(decoded_data))

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401, detail="Session cookie has expired.")
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=401, detail="Invalid session cookie.")

    @app.get("/auth/logout")
    async def manage_logout(request: Request, response: Response):
        """Reads the session cookie and extracts user info."""
        auth_cookie = _reconstruct_cookie(request, cookie_prefix="__session_data")
        # auth_cookie = request.cookies.get("__sessionData")

        if not auth_cookie:
            raise HTTPException(
                status_code=401, detail="No active session.")

        try:
            # Decode the JWT stored in the session cookie
            decoded_data = jwt.decode(
                auth_cookie, auth_client.secret_key, algorithms=["HS256"])

            # Extract the user ID (sub) from the decoded JWT
            user_id = decoded_data.get('user').get('sub')

            if not user_id:
                raise HTTPException(
                    status_code=400, detail="Invalid session cookie: Missing 'sub' claim.")

            auth_client.get(url=f"https://{auth_client.domain}/v2/logout")
            rt = decoded_data.get("refresh_token", None)
            if rt:
                rt_manager = RevokeToken(
                    auth_client.domain, auth_client.client_id, auth_client.client_secret)
                rt_manager.revoke_refresh_token(token=rt)

            for cookie_name in request.cookies.keys():
            # Delete all cookies, including split session cookies (e.g., __sessionData_0, __sessionData_1, etc.)
                if cookie_name.startswith("__session_data") or True:  
                    response.delete_cookie(key = cookie_name, path = "/auth")
            
            response.delete_cookie(key="__sessionData", path="/auth")
            auth_client.session_manager._delete_stored_session(user_id)

            # MODIFY RESPONSE to ensure it returns properly
            response.body = b'{"message": "logout successful"}'
            response.status_code = 200
            response.media_type = "application/json"

            return response

        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401, detail="Session cookie has expired.")
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=401, detail="Invalid session cookie.")

    @app.get("/auth/get_token")
    async def get_token(request: Request, audience: str | None = None,
     scope: str | None = None, connection: str | None = None):
        """Reads the session cookie and extracts user info."""
        auth_cookie = _reconstruct_cookie(request, cookie_prefix="__session_data")
        # auth_cookie = request.cookies.get("__sessionData")

        if not auth_cookie:
            raise HTTPException(
                status_code=401, detail="No active session.")

        if not audience or connection:
            raise HTTPException(
                status_code=401, detail="Missing audience or connection.")

        # TODO build the fact scenario where a token is required for a connection
        if connection:
            return JSONResponse(content=token)

        try:
            # Decode the stored session in the session cookie
            decoded_data = jwt.decode(
                auth_cookie, auth_client.secret_key, algorithms=["HS256"])

            # Check for existing token via audience
            token = {}
            sub = decoded_data.get("user").get("sub")

            if audience and "tokens" in decoded_data:
                # Verify existing token audience
                for token in decoded_data.get("tokens"):
                    
                    aud = token.get("aud")
                    # Check if audience is a list, possible if an AT is issued with openid and profile scopes
                    if isinstance(aud, list):  
                        aud = aud[0]
          
                    if aud == audience: 
                        if auth_client.token_manager._match_scopes(token.get("scope"),scope):
                            # found a match for audience and scope. checking if the token is not expired
                            if token.get("expires_at").get("epoch") > time.time():
                                return JSONResponse(content=token)
                            else:
                                # Token is expired, check if we have a refresh token
                                rt = auth_client.token_manager.get_refresh_token(user_id = sub)
                                # Try to get a new token using the refresh token
                                if rt:
                                    token =  auth_client.token_manager.refresh_tokens(refresh_token = rt, scope = scope)

                                    if token:
                                        cookie_session_data = await auth_client.session_manager.set_encrypted_session(token, user_id = sub)

                                        _set_cookie = await _split_cookie(response, max_size=4096, encoded_data=cookie_session_data, cookie_prefix="__session_data")

                                        # for some reason, setting the cookie in an outside function does not work!
                                        for key, value in _set_cookie.items():
                                            response.set_cookie(
                                            key=key,
                                            value=value,
                                            path="/auth",
                                            httponly=True,  # Prevent JavaScript access
                                            # secure=True,  # Send only over HTTPS
                                            samesite="Lax",  # Protect against CSRF
                                            )
            
                                        response.body = token
                                        response.status_code = 200

                                        return response
                                    else:
                                        raise HTTPException(status_code=401, detail="Failed to get a new token with refresh token.")
                                else:
                                    # Token is expired and no refesh token, get new token using /authorize endpoint
                                    try:
                                        token_url = auth_client.token_manager.get_new_token_url(audience = audience, scope = scope,  return_to = request.url)
                                        return RedirectResponse(url=token_url, status_code=302)
                                    except Exception as e:
                                        raise HTTPException(status_code=401, detail="Valid audience but failed to get new token.")
                        else:
                            # Token scope does not match, get new token using /authorize endpoint
                            try:
                                token_url = auth_client.token_manager.get_new_token_url(audience = audience, scope = scope,  return_to = request.url)
                                return RedirectResponse(url=token_url, status_code=302)
                            except Exception as e:
                                raise HTTPException(status_code=401, detail="Failed to get new token with different scopes.")
                if not token:
                    raise HTTPException(
                        status_code=401, detail="Failed to get an updated token for the audience.")

            # No tokens found, get new token using /authorize endpoint    
            try:
                token_url = auth_client.token_manager.get_new_token_url(audience = audience, scope = scope,  return_to = request.url)
                return RedirectResponse(url=token_url, status_code=302)
                
            except Exception as e:
                raise HTTPException(status_code=401, detail="Failed to get new token with different scopes.")
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401, detail="Session cookie has expired.")
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=401, detail="Invalid session cookie.")

        # if we are here, there is some error
        raise HTTPException(
            status_code=401, detail="Generic token error.")


    async def _split_cookie(response: Response, encoded_data: str,  max_size=4096, cookie_prefix="__session_data") -> dict[str, str]:
        
        # Calculate chunk size, ensuring space for the key name and additional characters
        chunk_size = max_size - len(cookie_prefix) - 10  
        cookies = {}

        # Split data into chunks and store in the response cookies
        for i in range(0, len(encoded_data), chunk_size):
            chunk_name = f"{cookie_prefix}_{i // chunk_size}"
            chunk_value = encoded_data[i:i + chunk_size]
            cookies[chunk_name] = chunk_value
            response.set_cookie(key=chunk_name, value=chunk_value, path="/auth", httponly=True, samesite="Lax")

        return cookies  # Returning for debugging/logging if needed
        
    def _reconstruct_cookie(request: Request, cookie_prefix="__session_data"):
        session_parts = []

        # Extract all cookies that match cookie_prefix
        for key, value in request.cookies.items():
            if key.startswith(cookie_prefix):
                index = int(key.split("_")[-1])  # Extract the index from the cookie name
                session_parts.append((index, value))

        if not session_parts:
            # No cookie found, return empty string
            return ""
            # raise HTTPException(status_code=400, detail="Session data not found in cookies")

        # Sort by index and reconstruct the full session string
        session_parts.sort()  # Sort by index
        full_encoded_data = "".join(part[1] for part in session_parts)  # Concatenate in order

        return full_encoded_data