from __future__ import annotations
from typing import Any

"""
Custom exceptions for authentication-related errors.
Provides specific exception types to handle different error scenarios.
"""
class AccessTokenForConnectionErrorCode:
    MISSING_REFRESH_TOKEN = "MISSING_REFRESH_TOKEN"
    FAILED_TO_RETRIEVE = "FAILED_TO_RETRIEVE"
    # Add more codes as needed

class AccessTokenForConnectionError(Exception):
    """Custom error when retrieving an access token for a federated connection fails."""
    def __init__(self, code: str, message: str, original_exception: Exception = None):
        super().__init__(message)
        self.code = code
        self.original_exception = original_exception