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


def update_state_data(
    audience: str,
    existing_state_data: Optional[Dict[str, Any]],
    token_response: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Update state data with new token information.
    
    Args:
        audience: Token audience
        existing_state_data: Existing state data or None
        token_response: Response from token endpoint
        
    Returns:
        Updated state data
    """
    # Start with existing data or empty dict
    state_data = existing_state_data or {}
    
    # Initialize token_sets if it doesn't exist
    if 'token_sets' not in state_data:
        state_data['token_sets'] = []
    
    # Create new token set
    new_token_set = {
        'audience': audience,
        'access_token': token_response.get('access_token', ''),
        'expires_at': int(time.time()) + token_response.get('expires_in', 3600)
    }
    
    if 'scope' in token_response:
        new_token_set['scope'] = token_response['scope']
    
    # Replace existing token set for this audience if it exists
    replaced = False
    for i, token_set in enumerate(state_data['token_sets']):
        if token_set.get('audience') == audience:
            state_data['token_sets'][i] = new_token_set
            replaced = True
            break
    
    # Add new token set if not replaced
    if not replaced:
        state_data['token_sets'].append(new_token_set)
    
    # Update refresh token if present
    if 'refresh_token' in token_response:
        state_data['refresh_token'] = token_response['refresh_token']
    
    # Update ID token and user info if present
    if 'id_token' in token_response:
        state_data['id_token'] = token_response['id_token']
    
    return state_data


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