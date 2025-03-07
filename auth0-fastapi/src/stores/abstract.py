"""
Abstract base classes for FastAPI-specific store implementations.
These adapt the core auth0-server-python stores to work with FastAPI.
"""

import sys
import os

# Dynamically add `src` folder to sys.path
current_dir = os.path.dirname(os.path.abspath(__file__))
sdk_src_path = os.path.abspath(os.path.join(current_dir, '../auth0-server-python/src'))
sys.path.insert(0, sdk_src_path)

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
from fastapi import Request, Response

from store.abstract import StateStore, TransactionStore
from error import StoreOptionsError


class FastAPITransactionStore(TransactionStore, ABC):
    """
    Abstract base class for FastAPI transaction stores.
    Provides common functionality for accessing request/response.
    """
    
    def __init__(self, secret: str):
        super().__init__({"secret": secret})
    
    def get_request_response(self, options: Optional[Dict[str, Any]] = None) -> Tuple[Request, Response]:
        """
        Extract request and response from options.
        
        Args:
            options: Dictionary containing request and response objects
            
        Returns:
            Tuple of (request, response)
            
        Raises:
            StoreOptionsError: If request or response is missing
        """
        if not options or "request" not in options:
            raise StoreOptionsError("Request object is required in store options")
        
        request = options["request"]
        response = options.get("response") or getattr(request.state, "auth0_response", None)
        
        if not response:
            raise StoreOptionsError("Response object not found in options or request.state")
            
        return request, response


class FastAPISessionStore(StateStore, ABC):
    """
    Abstract base class for FastAPI session stores.
    Provides common functionality for session management.
    """
    
    def __init__(self, secret: str, cookie_name: str, secure: Optional[bool], same_site: str, duration: int):
        """
        Initialize the session store.
        
        Args:
            secret: Secret for encryption
            cookie_name: Name of the session cookie
            secure: Whether to use secure cookies
            same_site: SameSite cookie attribute
            duration: Session duration in seconds
        """
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.secure = secure
        self.same_site = same_site
        self.duration = duration
    
    def get_request_response(self, options: Optional[Dict[str, Any]] = None) -> Tuple[Request, Response]:
        """
        Extract request and response from options.
        
        Args:
            options: Dictionary containing request and response objects
            
        Returns:
            Tuple of (request, response)
            
        Raises:
            StoreOptionsError: If request or response is missing
        """
        if not options or "request" not in options:
            raise StoreOptionsError("Request object is required in store options")
        
        request = options["request"]
        response = options.get("response") or getattr(request.state, "auth0_response", None)
        
        if not response:
            raise StoreOptionsError("Response object not found in options or request.state")
            
        return request, response