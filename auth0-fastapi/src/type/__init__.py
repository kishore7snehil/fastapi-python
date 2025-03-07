"""
Type definitions for auth0-fastapi.
These Pydantic models provide type safety and validation for all SDK data structures.
"""

from typing import Dict, List, Optional, Any, Union, Literal
from pydantic import BaseModel, Field, validator
from pydantic.color import Color


class CookieOptions(BaseModel):
    """
    Configuration options for cookies.
    Controls how session and transaction cookies are set.
    """
    name: str = "_a0_session"
    same_site: Literal["lax", "strict", "none"] = "lax"
    secure: Optional[bool] = None  # If None, will be auto-set based on request scheme
    http_only: bool = True
    path: str = "/"
    max_age: Optional[int] = None  # If None, will be calculated from session duration


class SessionConfig(BaseModel):
    """
    Configuration for session behavior.
    Controls session lifetime and automatic extension.
    """
    rolling: bool = True  # Whether to extend session on activity
    absolute_duration: int = 259200  # 3 days in seconds - max lifetime
    inactivity_duration: int = 86400  # 1 day in seconds - timeout after inactivity
    cookie: Optional[CookieOptions] = None


class SessionOptions(BaseModel):
    """
    Options for session storage.
    Configures where and how session data is stored.
    """
    session_type: Literal["cookie", "memory", "custom"] = "cookie"
    cookie_name: str = "_a0_session"
    cookie_secure: Optional[bool] = None
    cookie_same_site: Literal["lax", "strict", "none"] = "lax"
    session_duration: int = 259200  # 3 days in seconds
    backend: Optional[Any] = None  # Custom session backend


class Auth0Options(BaseModel):
    """
    Configuration options for Auth0 FastAPI integration.
    """
    domain: str
    client_id: str
    client_secret: str
    redirect_uri: Optional[str] = None
    app_base_url: Optional[str] = None
    audience: Optional[str] = None
    scope: str = "openid profile email"
    secret: str
    session: SessionOptions = Field(default_factory=SessionOptions)
    transaction_cookie_name: str = "_a0_tx"
    routes_prefix: str = "/auth"
    mount_routes: bool = True
    login_path: str = "/login"
    logout_path: str = "/logout"
    callback_path: str = "/callback"
    backchannel_logout_path: str = "/backchannel-logout"
    
    @validator('domain')
    def domain_must_not_have_protocol(cls, v):
        if v.startswith(('http://', 'https://')):
            raise ValueError('domain should not include protocol (http:// or https://)')
        return v


class UserProfile(BaseModel):
    """
    User profile information from Auth0.
    Contains standard OIDC claims about the authenticated user.
    """
    sub: str
    name: Optional[str] = None
    nickname: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    picture: Optional[str] = None
    email: Optional[str] = None
    email_verified: Optional[bool] = None
    org_id: Optional[str] = None
    
    class Config:
        extra = "allow"  # Allow additional fields not defined in the model


class TokenSet(BaseModel):
    """
    Set of tokens issued by Auth0.
    """
    access_token: str
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    expires_in: int
    scope: Optional[str] = None
    
    class Config:
        extra = "allow"  # Allow additional fields returned by Auth0


class LogoutOptions(BaseModel):
    """
    Options for logout operations.
    """
    return_to: Optional[str] = None  # URL to redirect after logout


class LoginOptions(BaseModel):
    """
    Options for login operations.
    """
    return_to: Optional[str] = None  # URL to redirect after login
    audience: Optional[str] = None  # API audience to request access for
    scope: Optional[str] = None  # Override the default scope
    prompt: Optional[Literal["none", "login", "consent", "select_account"]] = None
    max_age: Optional[int] = None  # Maximum authentication age in seconds
    ui_locales: Optional[str] = None  # Preferred languages for UI
    
    class Config:
        extra = "allow"  # Allow additional OIDC parameters


class StoreOptions(BaseModel):
    """
    Options passed to store operations.
    Contains request and response objects for cookie handling.
    """
    request: Any  # FastAPI Request object
    response: Optional[Any] = None  # FastAPI Response object