"""
Cookie-based implementation of the transaction store.
Used for short-lived transaction data during authentication.
"""

import time
from typing import Dict, Any, Optional

from fastapi import Request, Response

from .abstract import FastAPITransactionStore
from utils import calculate_cookie_params


class CookieTransactionStore(FastAPITransactionStore):
    """
    Transaction store implementation using cookies in FastAPI.
    Used for temporary data during the authentication flow.
    """
    
    def __init__(
        self, 
        secret: str,
        cookie_name: str = "_a0_tx", 
        secure: Optional[bool] = None, 
        same_site: str = "lax"
    ):
        """
        Initialize cookie transaction store.
        
        Args:
            secret: Secret for encryption
            cookie_name: Name of the transaction cookie
            secure: Whether to use secure cookies
            same_site: SameSite cookie attribute
        """
        super().__init__(secret)
        self.cookie_name = cookie_name
        self.secure = secure
        self.same_site = same_site
    
    async def set(
        self, 
        identifier: str, 
        data: Dict[str, Any], 
        remove_if_expires: bool = False,
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store transaction data in a cookie.
        
        Args:
            identifier: Transaction identifier
            data: Transaction data to store
            remove_if_expires: Whether to remove data when it expires
            options: Dictionary containing request and response objects
        """
        request, response = self.get_request_response(options)
        
        # Calculate expiration (60 seconds for transactions)
        expiration = int(time.time()) + 60
        
        # Encrypt the data using the core SDK's encryption
        encrypted_data = self.encrypt(identifier, data, expiration)
        
        # Get cookie parameters
        cookie_params = calculate_cookie_params(
            self.secure, 
            self.same_site, 
            request.url.scheme
        )
        
        # Set the cookie in the response
        response.set_cookie(
            key=identifier,
            value=encrypted_data,
            max_age=60,
            httponly=True,
            secure=cookie_params["secure"],
            samesite=cookie_params["samesite"],
            path="/"
        )
    
    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve transaction data from a cookie.
        
        Args:
            identifier: Transaction identifier
            options: Dictionary containing request and response objects
            
        Returns:
            Transaction data or None if not found
        """
        request, _ = self.get_request_response(options)
        
        # Get the cookie from the request
        encrypted_data = request.cookies.get(identifier)
        if not encrypted_data:
            return None
        
        try:
            # Decrypt the data using the core SDK's decryption
            return await self.decrypt(identifier, encrypted_data)
        except Exception:
            return None
    
    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete the transaction cookie.
        
        Args:
            identifier: Transaction identifier
            options: Dictionary containing request and response objects
        """
        _, response = self.get_request_response(options)
        
        # Clear the cookie
        response.delete_cookie(
            key=identifier,
            path="/"
        )