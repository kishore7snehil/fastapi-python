from typing import Dict, Any, Optional
from fastapi import Response, Request

import os
from encryption import encrypt, decrypt

class CookieStore:
    """
    Utility class for managing HTTP cookies in FastAPI applications.
    Handles cookie operations including splitting large cookies,
    setting with security attributes, and retrieving/combining split cookies.
    """
    def __init__(self, 
                 default_path: str = "/auth", 
                 httponly: bool = True, 
                 secure: bool = True,
                 samesite: str = "Lax", 
                 max_age: int = 86400):
        """
        Initialize cookie store with default settings.
        Args:
            default_path: Cookie path attribute
            httponly: Prevent JavaScript access to cookie
            secure: Only send cookie over HTTPS
            samesite: CSRF protection (Lax, Strict, None)
            max_age: Cookie lifetime in seconds (default 24h)
        """
        self.default_settings = {
            "path": default_path,
            "httponly": httponly,
            "secure": secure,
            "samesite": samesite,
            "max_age": max_age
        }
        self.max_cookie_size = 4096  # Browser size limit
        self.cookie_prefix = "__session_data"

        #Encryption Configuration
        self.salt = "e4f3c1a2b3d4e5f67890abcdef123456"
        self.secret = os.environ.get('AUTH0_SECRET_KEY')


    def split_cookie(self, response: Response, encoded_data: str) -> dict[str, str]:
        """
        Split large cookie data into multiple cookies if needed.
        Args:
            response: FastAPI Response object
            encoded_data: Cookie data to split
            max_size: Maximum size per cookie
            cookie_prefix: Prefix for cookie names
        Returns:
            Dictionary of cookie chunks
        """
        # Calculate chunk size, ensuring space for the key name and additional characters
        chunk_size = self.max_cookie_size - len(self.cookie_prefix) - 10
        cookies = {}
        # Split data into chunks and store in the response cookies
        for i in range(0, len(encoded_data), chunk_size):
            chunk_name = f"{self.cookie_prefix}_{i // chunk_size}"
            chunk_value = encoded_data[i:i + chunk_size]
            cookies[chunk_name] = chunk_value
            response.set_cookie(
                key=chunk_name, 
                value=chunk_value, 
                path="/auth", 
                httponly=True, 
                samesite="Lax"
            )
        return cookies
    
    def get(self, request: Request):
        """
        Reconstruct session data from multiple cookies.
        Args:
            request: FastAPI Request object
            cookie_prefix: Prefix used for session cookies
        Returns:
            Reconstructed session data
        Raises:
            HTTPException: If no session data is found
        """
        session_parts = []
        # Extract all cookies that match cookie_prefix
        for key, value in request.cookies.items():
            if key.startswith(self.cookie_prefix):
                index = int(key.split("_")[-1])
                session_parts.append((index, value))
        if not session_parts:
            return ""
 
        session_parts.sort()  # Sort by index
        full_encoded_data = "".join(part[1] for part in session_parts)
        decrypted_data = decrypt(full_encoded_data, self.secret, self.salt)
        return decrypted_data
    
    def set(self, 
            response: Response, 
            data: str, 
            **cookie_options) -> Response:
        """
        Set cookie data with appropriate splitting if needed.
        Args:
            response: FastAPI Response object
            data: Cookie data to set
            max_size: Maximum size per cookie
            prefix: Prefix for cookie names
            **cookie_options: Override default cookie settings
        Returns:
            Modified Response object with cookies set
        """
        # Merge default settings with any overrides
        settings = {**self.default_settings, **cookie_options}
        #Encrypt the data
        encrypted_data = encrypt(data, self.secret, self.salt)
        # Split cookie if needed
        cookies = self.split_cookie(response, encrypted_data)
        return response
    
    
    def delete(self, response: Response) -> Response:
        """
        Clear all cookies with the given prefix.
        Args:
            response: FastAPI Response object
            prefix: Prefix for cookies to clear
        Returns:
            Modified Response with cookies cleared
        """
        # Clear the main cookie
        response.delete_cookie(key=self.cookie_prefix, path=self.default_settings["path"])
        # Clear chunked cookies (we don't know how many there might be)
        # In a real implementation, you might track this somewhere
        for i in range(20):  # Assuming a reasonable upper limit
            chunk_key = f"{self.cookie_prefix}_{i}"
            response.delete_cookie(key=chunk_key, path=self.default_settings["path"])
        return response
    