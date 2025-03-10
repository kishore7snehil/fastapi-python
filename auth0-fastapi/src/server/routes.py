from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import RedirectResponse
from typing import Optional
from auth.auth_client import AuthClient  # adjust relative import as needed

router = APIRouter()

def get_auth_client(request: Request) -> AuthClient:
    """
    Dependency function to retrieve the AuthClient instance.
    Assumes the client is set on the FastAPI application state.
    """
    auth_client = request.app.state.auth_client
    if not auth_client:
        raise HTTPException(status_code=500, detail="Authentication client not configured.")
    return auth_client

@router.get("/auth/login")
async def login(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
    """
    Endpoint to initiate the login process.
    Optionally accepts a 'returnTo' query parameter and passes it as part of the app state.
    Redirects the user to the Auth0 authorization URL.
    """
  
    return_to: Optional[str] = request.query_params.get("returnTo")
    auth_url = await auth_client.start_login(
        request, 
        app_state={"returnTo": return_to} if return_to else None,
        store_options={"response": response}
    )

    redirect_response = RedirectResponse(url=auth_url)
    if "set-cookie" in response.headers:
        for cookie in response.headers.getlist("set-cookie"):
            redirect_response.headers.append("set-cookie", cookie)
    return redirect_response

@router.get("/auth/callback")
async def callback(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
    """
    Endpoint to handle the callback after Auth0 authentication.
    Processes the callback URL and completes the login flow.
    Redirects the user to a post-login URL based on appState or a default.
    """
    full_callback_url = str(request.url)
    try:
        session_data = await auth_client.complete_login(request, full_callback_url, store_options={"request": request, "response": response})
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    
    # Extract the returnTo URL from the appState if available.
    return_to = session_data.get("app_state", {}).get("returnTo")
    
    default_redirect = request.app.state.config.app_base_url  # Assuming config is stored on app.state
    
    # Create a RedirectResponse and merge Set-Cookie headers from the original response
    redirect_response = RedirectResponse(url=return_to or default_redirect)
    # Merge cookie headers (if any) from `response`
    if "set-cookie" in response.headers:
        # If multiple Set-Cookie headers exist, they might be a list.
        cookies = response.headers.getlist("set-cookie") if hasattr(response.headers, "getlist") else [response.headers["set-cookie"]]
        for cookie in cookies:
            redirect_response.headers.append("set-cookie", cookie)
    return redirect_response

@router.get("/auth/logout")
async def logout(request: Request, response: Response, auth_client: AuthClient = Depends(get_auth_client)):
    """
    Endpoint to handle logout.
    Clears the session cookie (if applicable) and generates a logout URL,
    then redirects the user to Auth0's logout endpoint.
    """
    try:
        logout_url = await auth_client.logout(return_to=str(request.app.state.config.app_base_url), store_options={"response": response})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    # Create a redirect response
    redirect_response = RedirectResponse(url=logout_url)
    
    # Merge cookie deletion headers from temp_response into redirect_response
    if "set-cookie" in response.headers:
        # In FastAPI, headers are a multi-dict so you can loop over them
        for cookie in response.headers.getlist("set-cookie"):
            redirect_response.headers.append("set-cookie", cookie)
            
    return redirect_response

@router.post("/auth/backchannel-logout")
async def backchannel_logout(request: Request, auth_client: AuthClient = Depends(get_auth_client)):
    """
    Endpoint to process backchannel logout notifications.
    Expects a JSON body with a 'logout_token'.
    Returns 204 No Content on success.
    """
    body = await request.json()
    logout_token = body.get("logout_token")
    if not logout_token:
        raise HTTPException(status_code=400, detail="Missing 'logout_token' in request body.")
    
    try:
        await auth_client.handle_backchannel_logout(logout_token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return Response(status_code=204)
