"""
Cookie-based implementation of the session store.
Stores encrypted session data directly in cookies.
"""

import time
import math
from typing import Dict, Any, Optional, List

from fastapi import Request, Response

from .abstract import FastAPISessionStore


class StatelessSessionStore(FastAPISessionStore):
    """
    Session store implementation using cookies.
    Handles chunking for large session data.
    """
    
    def __init__(
        self, 
        secret: str, 
        cookie_name: str = "_a0_session", 
        secure: Optional[bool] = None, 
        same_site: str = "lax", 
        duration: int = 259200
    ):
        """
        Initialize the stateless session store.
        
        Args:
            secret: Secret for encryption
            cookie_name: Name of the session cookie
            secure: Whether to use secure cookies
            same_site: SameSite cookie attribute
            duration: Session duration in seconds
        """
        super().__init__(secret, cookie_name, secure, same_site, duration)
        self.chunk_size = 4000  # Maximum size for cookie chunks
    
    async def set(
        self, 
        identifier: str, 
        data: Dict[str, Any], 
        remove_if_expires: bool = False,
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store session data in cookies, chunked if necessary.
        
        Args:
            identifier: Session identifier
            data: Session data to store
            remove_if_expires: Whether to remove data when it expires
            options: Dictionary containing request and response objects
        """
        request, response = self.get_request_response(options)
        
        # Calculate expiration
        created_at = data.get("internal", {}).get("created_at", int(time.time()))
        max_age = self.duration
        
        expiration = int(time.time()) + max_age
        
        # Encrypt the data
        encrypted_data = await self.encrypt(identifier, data, expiration)
        
        # Check if we need to chunk the data
        if len(encrypted_data) <= self.chunk_size:
            # Data fits in a single cookie
            response.set_cookie(
                key=self.cookie_name,
                value=encrypted_data,
                max_age=max_age,
                httponly=True,
                secure=self.secure if self.secure is not None else request.url.scheme == "https",
                samesite=self.same_site,
                path="/"
            )
            return
        
        # Need to chunk the data
        chunk_count = math.ceil(len(encrypted_data) / self.chunk_size)
        
        # Create the chunks
        chunks = []
        for i in range(chunk_count):
            start = i * self.chunk_size
            end = min(start + self.chunk_size, len(encrypted_data))
            chunk_name = f"{self.cookie_name}.{i}"
            chunk_value = encrypted_data[start:end]
            chunks.append((chunk_name, chunk_value))
        
        # Remove any existing cookies
        existing_keys = self._get_cookie_keys(request)
        for key in existing_keys:
            if key.startswith(f"{self.cookie_name}."):
                response.delete_cookie(key, path="/")
        
        # Set the new chunk cookies
        for name, value in chunks:
            response.set_cookie(
                key=name,
                value=value,
                max_age=max_age,
                httponly=True,
                secure=self.secure if self.secure is not None else request.url.scheme == "https",
                samesite=self.same_site,
                path="/"
            )
    
    async def get(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve session data from cookies, handling chunked data.
        
        Args:
            identifier: Session identifier
            options: Dictionary containing request and response objects
            
        Returns:
            Session data or None if not found
        """
        request, _ = self.get_request_response(options)
        
        # Check for a single cookie first
        encrypted_data = request.cookies.get(self.cookie_name)
        
        if not encrypted_data:
            # Check for chunked cookies
            chunks = []
            i = 0
            while True:
                chunk = request.cookies.get(f"{self.cookie_name}.{i}")
                if chunk:
                    chunks.append(chunk)
                    i += 1
                else:
                    break
            
            if not chunks:
                return None
            
            # Combine chunks
            encrypted_data = "".join(chunks)
        
        try:
            # Decrypt the data
            return await self.decrypt(identifier, encrypted_data)
        except Exception:
            return None
    
    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete all session cookies.
        
        Args:
            identifier: Session identifier
            options: Dictionary containing request and response objects
        """
        request, response = self.get_request_response(options)
        
        # Delete the main cookie
        response.delete_cookie(self.cookie_name, path="/")
        
        # Delete any chunk cookies
        cookie_keys = self._get_cookie_keys(request)
        for key in cookie_keys:
            if key.startswith(f"{self.cookie_name}."):
                response.delete_cookie(key, path="/")
    
    async def delete_by_logout_token(
        self, 
        claims: Dict[str, Any], 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete sessions based on logout token claims.
        
        Args:
            claims: Claims from the logout token
            options: Dictionary containing request and response objects
        """
        # For cookie-based stores, we just need to delete the current session
        await self.delete(self.cookie_name, options)
    
    def _get_cookie_keys(self, request: Request) -> List[str]:
        """
        Get all cookie keys from the request.
        
        Args:
            request: FastAPI request object
            
        Returns:
            List of cookie names
        """
        return list(request.cookies.keys())