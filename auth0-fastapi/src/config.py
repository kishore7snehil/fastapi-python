from pydantic import BaseModel, AnyUrl, Field
from typing import Optional, Dict, Any

class Auth0Config(BaseModel):
    """
    Configuration settings for the FastAPI SDK integrating auth0-server-python.
    """
    domain: str
    client_id: str = Field(..., alias="clientId")
    client_secret: str = Field(..., alias="clientSecret")
    app_base_url: AnyUrl = Field(..., alias="appBaseUrl", description="Base URL of your application (e.g., https://example.com)")
    secret: str = Field(..., description="Secret used for encryption and signing cookies")
    audience: Optional[str] = Field(None, description="Target audience for tokens (if applicable)")
    authorization_params: Optional[Dict[str, Any]] = Field(None, description="Additional parameters to include in the authorization request")
    pushed_authorization_requests: bool = Field(False, description="Whether to use pushed authorization requests")
    mount_routes: bool = Field(True, description="Flag to mount the default auth routes")
    cookie_name: str = Field("auth0_session", description="Name of the cookie storing session data")
    session_expiration: int = Field(259200, description="Session expiration time in seconds (default: 3 days)")
    # Optional: add additional configuration like signing keys/algorithms if needed
    client_assertion_signing_key: Optional[str] = Field(None, description="Signing key for client assertions, if applicable")
    client_assertion_signing_alg: Optional[str] = Field(None, description="Signing algorithm for client assertions, if applicable")

    class Config:
        populate_by_name = True
