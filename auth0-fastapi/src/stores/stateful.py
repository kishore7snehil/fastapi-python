"""
Server-side implementation of the session store.
Stores only a session ID in cookies with actual data in a backend store.
"""

import time
import secrets
import string
from typing import Dict, Any, Optional, Protocol, Callable
from abc import ABC, abstractmethod

from fastapi import Request, Response

from .abstract import FastAPISessionStore


def generate_random_string(length: int = 32) -> str:
    """Generate a cryptographically secure random string."""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


class SessionBackend(Protocol):
    """Protocol defining the interface for session storage backends."""
    
    async def set(self, key: str, data: Dict[str, Any], expiration: int) -> None:
        """Store session data with the given key."""
        ...
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data by key."""
        ...
    
    async def delete(self, key: str) -> None:
        """Delete session data by key."""
        ...
    
    async def delete_by_claims(self, sub: str, sid: str) -> None:
        """Delete sessions matching subject and session ID claims."""
        ...


class MemorySessionBackend:
    """
    In-memory session storage backend.
    
    Warning: This is not suitable for production in multi-process environments.
    """
    
    def __init__(self):
        self._storage = {}  # key -> (data, expiration)
    
    async def set(self, key: str, data: Dict[str, Any], expiration: int) -> None:
        """Store session data with the given key."""
        self._storage[key] = (data, expiration)
        self._clean_expired()
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve session data by key."""
        self._clean_expired()
        if key not in self._storage:
            return None
        
        data, expiration = self._storage[key]
        if expiration < time.time():
            del self._storage[key]
            return None
            
        return data
    
    async def delete(self, key: str) -> None:
        """Delete session data by key."""
        if key in self._storage:
            del self._storage[key]
    
    async def delete_by_claims(self, sub: str, sid: str) -> None:
        """Delete sessions matching subject and session ID claims."""
        keys_to_delete = []
        
        for key, (data, _) in self._storage.items():
            internal = data.get("internal", {})
            user = data.get("user", {})
            
            if (internal.get("sid") == sid and 
                user.get("sub") == sub):
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self._storage[key]
    
    def _clean_expired(self) -> None:
        """Remove expired sessions."""
        now = time.time()
        expired_keys = [
            key for key, (_, expiration) in self._storage.items()
            if expiration < now
        ]
        
        for key in expired_keys:
            del self._storage[key]


class StatefulSessionStore(FastAPISessionStore):
    """
    Session store implementation using a backend store with a cookie reference.
    Stores a session ID in cookies with the actual data in the backend.
    """
    
    def __init__(
        self, 
        secret: str, 
        backend: SessionBackend,
        cookie_name: str = "_a0_session", 
        secure: Optional[bool] = None, 
        same_site: str = "lax", 
        duration: int = 259200
    ):
        """
        Initialize stateful session store.
        
        Args:
            secret: Secret for encryption
            backend: Session storage backend
            cookie_name: Name of the session cookie
            secure: Whether to use secure cookies
            same_site: SameSite cookie attribute
            duration: Session duration in seconds
        """
        super().__init__(secret, cookie_name, secure, same_site, duration)
        self.backend = backend
    
    async def set(
        self, 
        identifier: str, 
        data: Dict[str, Any], 
        remove_if_expires: bool = False,
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Store session data in backend with ID in cookie.
        
        Args:
            identifier: Session identifier
            data: Session data to store
            remove_if_expires: Whether to remove data when it expires
            options: Dictionary containing request and response objects
        """
        request, response = self.get_request_response(options)
        
        # Get existing session ID or generate a new one
        session_id = await self._get_session_id(request)
        if not session_id:
            session_id = generate_random_string(32)
        
        # Calculate expiration
        expiration = int(time.time()) + self.duration
        
        # Add session ID to the data for backchannel logout
        if "internal" not in data:
            data["internal"] = {}
        data["internal"]["sid"] = session_id
        
        # Store data in backend
        await self.backend.set(session_id, data, expiration)
        
        # Set cookie with session ID
        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            max_age=self.duration,
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
        Retrieve session data from backend using cookie session ID.
        
        Args:
            identifier: Session identifier
            options: Dictionary containing request and response objects
            
        Returns:
            Session data or None if not found
        """
        request, _ = self.get_request_response(options)
        
        # Get session ID from cookie
        session_id = await self._get_session_id(request)
        if not session_id:
            return None
        
        # Get data from backend
        return await self.backend.get(session_id)
    
    async def delete(
        self, 
        identifier: str, 
        options: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Delete session from backend and clear cookie.
        
        Args:
            identifier: Session identifier
            options: Dictionary containing request and response objects
        """
        request, response = self.get_request_response(options)
        
        # Get session ID from cookie
        session_id = await self._get_session_id(request)
        if session_id:
            # Delete from backend
            await self.backend.delete(session_id)
        
        # Clear cookie
        response.delete_cookie(self.cookie_name, path="/")
    
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
        # Get subject and session ID from claims
        sub = claims.get("sub")
        sid = claims.get("sid")
        
        if not sub or not sid:
            return
        
        # Delete matching sessions from backend
        await self.backend.delete_by_claims(sub, sid)
    
    async def _get_session_id(self, request: Request) -> Optional[str]:
        """
        Get session ID from request cookies.
        
        Args:
            request: FastAPI request object
            
        Returns:
            Session ID or None if not found
        """
        return request.cookies.get(self.cookie_name)