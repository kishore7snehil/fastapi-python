"""
Utility functions for auth0-server-python SDK.
These helpers provide common functionality used across the SDK.
"""

import base64
import hashlib
import secrets
import string
import time
from typing import Dict, Any, Optional
from urllib.parse import urlencode, urlparse, parse_qs


def generate_random_string(length: int = 64) -> str:
    """
    Generate a cryptographically secure random string.
    
    Args:
        length: Length of the string to generate
        
    Returns:
        Random string with the specified length
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_pkce_pair() -> Dict[str, str]:
    """
    Generate a PKCE code verifier and challenge pair.
    Used to secure the OAuth 2.0 authorization code flow.
    
    Returns:
        Dictionary containing 'code_verifier' and 'code_challenge'
    """
    code_verifier = generate_random_string(64)
    code_challenge = generate_code_challenge(code_verifier)
    
    return {
        'code_verifier': code_verifier,
        'code_challenge': code_challenge
    }


def generate_code_challenge(code_verifier: str) -> str:
    """
    Generate a PKCE code challenge from a code verifier.
    
    Args:
        code_verifier: The code verifier string
        
    Returns:
        Code challenge string (base64url-encoded SHA256 hash)
    """
    code_challenge_digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_digest).decode('utf-8')
    return code_challenge.rstrip('=')  # Remove padding


def build_url(base_url: str, params: Dict[str, Any]) -> str:
    """
    Build a URL with query parameters.
    
    Args:
        base_url: Base URL without query parameters
        params: Dictionary of query parameters to add
        
    Returns:
        Complete URL with query parameters
    """
    query_string = urlencode(params)
    separator = '?' if '?' not in base_url else '&'
    return f"{base_url}{separator}{query_string}" if query_string else base_url


def parse_url_params(url: str) -> Dict[str, str]:
    """
    Parse query parameters from a URL.
    
    Args:
        url: URL to parse
        
    Returns:
        Dictionary of query parameters (single values only)
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)
    
    # Convert list values to single strings
    return {k: v[0] if v and len(v) > 0 else '' for k, v in query_params.items()}

def create_logout_url(domain: str, client_id: str, return_to: Optional[str] = None) -> str:
    """
    Create an Auth0 logout URL.
    
    Args:
        domain: Auth0 domain
        client_id: Auth0 client ID
        return_to: URL to redirect to after logout
        
    Returns:
        Complete logout URL
    """
    base_url = f"https://{domain}/v2/logout"
    params = {"client_id": client_id}
    
    if return_to:
        params["returnTo"] = return_to
    
    return build_url(base_url, params)


def update_state_data(
    audience: str,
    state_data: Optional[Dict[str, Any]],
    token_endpoint_response: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Utility function to update the state with a new response from the token endpoint
    
    Args:
        audience: The audience of the token endpoint response
        state_data: The existing state data to update, or None if no state data available
        token_endpoint_response: The response from the token endpoint
        
    Returns:
        Updated state data
    """
    current_time = int(time.time())
    
    if state_data:
        # Check if we need to add a new token set or update an existing one
        is_new_token_set = True
        token_sets = state_data.get("token_sets", [])
        
        for token_set in token_sets:
            if (token_set.get("audience") == audience and 
                token_set.get("scope") == token_endpoint_response.get("scope")):
                is_new_token_set = False
                break
        
        # Create the updated token set
        updated_token_set = {
            "audience": audience,
            "access_token": token_endpoint_response.get("access_token"),
            "scope": token_endpoint_response.get("scope"),
            "expires_at": current_time + int(token_endpoint_response.get("expires_in", 0))
        }
        
        # Update or add the token set
        if is_new_token_set:
            token_sets = token_sets + [updated_token_set]
        else:
            token_sets = [
                updated_token_set if (ts.get("audience") == audience and 
                                    ts.get("scope") == token_endpoint_response.get("scope"))
                else ts
                for ts in token_sets
            ]
        
        # Return updated state data
        return {
            **state_data,
            "id_token": token_endpoint_response.get("id_token"),
            "refresh_token": token_endpoint_response.get("refresh_token") or state_data.get("refresh_token"),
            "token_sets": token_sets
        }
    else:
        # Create completely new state data
        user = token_endpoint_response.get("claims", {})
        return {
            "user": user,
            "id_token": token_endpoint_response.get("id_token"),
            "refresh_token": token_endpoint_response.get("refresh_token"),
            "token_sets": [
                {
                    "audience": audience,
                    "access_token": token_endpoint_response.get("access_token"),
                    "scope": token_endpoint_response.get("scope"),
                    "expires_at": current_time + int(token_endpoint_response.get("expires_in", 0))
                }
            ],
            "internal": {
                "sid": user.get("sid", ""),
                "created_at": current_time
            }
        }


def update_state_data_for_connection_token_set(
    options: Dict[str, Any],
    state_data: Dict[str, Any],
    token_endpoint_response: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Update state data with connection token set information
    
    Args:
        options: Options containing connection details
        state_data: Existing state data
        token_endpoint_response: Response from token endpoint
        
    Returns:
        Updated state data
    """
    # Initialize connection_token_sets if it doesn't exist
    connection_token_sets = state_data.get("connection_token_sets", [])
    
    # Check if we need to add a new token set or update an existing one
    is_new_token_set = True
    
    for token_set in connection_token_sets:
        if (token_set.get("connection") == options.get("connection") and 
            (not options.get("login_hint") or token_set.get("login_hint") == options.get("login_hint"))):
            is_new_token_set = False
            break
    
    # Create the connection token set
    connection_token_set = {
        "connection": options.get("connection"),
        "login_hint": options.get("login_hint"),
        "access_token": token_endpoint_response.get("access_token"),
        "scope": token_endpoint_response.get("scope"),
        "expires_at": int(time.time()) + int(token_endpoint_response.get("expires_in", 0))
    }
    
    # Update or add the token set
    if is_new_token_set:
        connection_token_sets = connection_token_sets + [connection_token_set]
    else:
        connection_token_sets = [
            connection_token_set if (ts.get("connection") == options.get("connection") and 
                                    (not options.get("login_hint") or 
                                     ts.get("login_hint") == options.get("login_hint")))
            else ts
            for ts in connection_token_sets
        ]
    
    # Return updated state data
    return {
        **state_data,
        "connection_token_sets": connection_token_sets
    }