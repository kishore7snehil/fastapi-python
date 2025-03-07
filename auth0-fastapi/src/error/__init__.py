"""
Custom error classes for auth0-fastapi.
"""

class Auth0Error(Exception):
    """Base class for all Auth0 errors."""
    
    def __init__(self, message=None):
        self.message = message
        super().__init__(message)


class MissingTransactionError(Auth0Error):
    """
    Error raised when a required transaction is missing.
    This typically happens during the callback phase when the transaction
    from the initial authorization request cannot be found.
    """
    code = "missing_transaction_error"
    
    def __init__(self, message=None):
        super().__init__(message or "The transaction is missing.")
        self.name = "MissingTransactionError"


class ApiError(Auth0Error):
    """
    Error raised when an API request to Auth0 fails.
    Contains details about the original error from Auth0.
    """
    
    def __init__(self, code: str, message: str, cause=None):
        super().__init__(message)
        self.code = code
        self.cause = cause
        
        # Extract additional error details if available
        if cause:
            self.error = getattr(cause, "error", None)
            self.error_description = getattr(cause, "error_description", None)
        else:
            self.error = None
            self.error_description = None


class AccessTokenError(Auth0Error):
    """Error raised when there's an issue with access tokens."""
    
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.name = "AccessTokenError"


class MissingRequiredArgumentError(Auth0Error):
    """
    Error raised when a required argument is missing.
    Includes the name of the missing argument in the error message.
    """
    code = "missing_required_argument_error"
    
    def __init__(self, argument: str):
        message = f"The argument '{argument}' is required but was not provided."
        super().__init__(message)
        self.name = "MissingRequiredArgumentError"
        self.argument = argument


class BackchannelLogoutError(Auth0Error):
    """
    Error raised during backchannel logout processing.
    This can happen when validating or processing logout tokens.
    """
    code = "backchannel_logout_error"
    
    def __init__(self, message: str):
        super().__init__(message)
        self.name = "BackchannelLogoutError"


class ConfigurationError(Auth0Error):
    """
    Error raised when there's an issue with the Auth0 configuration.
    """
    code = "configuration_error"
    
    def __init__(self, message: str):
        super().__init__(message)
        self.name = "ConfigurationError"


class StoreOptionsError(Auth0Error):
    """
    Error raised when store options are missing or invalid.
    """
    code = "store_options_error"
    
    def __init__(self, message: str = "Request and Response objects are required in store options"):
        super().__init__(message)
        self.name = "StoreOptionsError"


# Error code enumerations for consistent error handling

class AccessTokenErrorCode:
    """Error codes for access token operations."""
    MISSING_SESSION = "missing_session"
    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_REFRESH_TOKEN = "failed_to_refresh_token"
    FAILED_TO_REQUEST_TOKEN = "failed_to_request_token"


class AccessTokenForConnectionErrorCode:
    """Error codes for connection-specific token operations."""
    MISSING_REFRESH_TOKEN = "missing_refresh_token"
    FAILED_TO_RETRIEVE = "failed_to_retrieve"