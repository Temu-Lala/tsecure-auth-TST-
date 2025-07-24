class TSecureAuthError(Exception):
    """Base exception for all tsecure-auth errors."""
    pass

class InvalidTokenError(TSecureAuthError):
    """Raised when a token is invalid, expired, or tampered with."""
    pass

class ConfigurationError(TSecureAuthError):
    """Raised for configuration-related errors."""
    pass
