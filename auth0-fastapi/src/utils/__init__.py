"""
Utility functions for auth0-fastapi.
"""

import secrets
import string
from typing import Dict, Any
from fastapi import Request

from error import StoreOptionsError


def get_store_options(request: Request) -> Dict[str, Any]:
    """
    Create store options with request and response context.
    
    Args:
        request: FastAPI request object
        
    Returns:
        Dictionary containing request and response objects
        
    Raises:
        StoreOptionsError: If response cannot be found in request state
    """
    response = getattr(request.state, "auth0_response", None)
    if not response:
        raise StoreOptionsError("Response object not found in request state")
    
    return {
        "request": request,
        "response": response
    }


def generate_random_string(length: int = 32) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length: Length of the string to generate
        
    Returns:
        Random string of the specified length
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def calculate_cookie_params(secure: bool, same_site: str, url_scheme: str) -> Dict[str, Any]:
    """
    Calculate secure cookie parameters based on configuration and request scheme.
    
    Args:
        secure: Whether to use secure cookies
        same_site: SameSite cookie attribute
        url_scheme: URL scheme from request
        
    Returns:
        Dictionary of cookie parameters
    """
    # Auto-determine secure flag based on scheme if not explicitly set
    effective_secure = secure if secure is not None else (url_scheme == "https")
    
    # If using 'none' for SameSite, secure must be True
    if same_site == "none" and not effective_secure:
        effective_secure = True
    
    return {
        "secure": effective_secure,
        "samesite": same_site
    }


def format_auth0_error(error: str, description: str = None) -> str:
    """
    Format Auth0 error for display.
    
    Args:
        error: Error code
        description: Error description
        
    Returns:
        Formatted error message
    """
    if description:
        return f"{error}: {description}"
    return error
