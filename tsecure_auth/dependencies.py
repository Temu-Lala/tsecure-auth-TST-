from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from .core.security import TSTCipher, verify_token
from .services.user_service import UserService
from .services.token_service import TokenService
from .services.threat_service import ThreatService
from .models.token import TokenPayload
from .core.config import settings
from .exceptions import InvalidTokenError, ConfigurationError
from .services.database import get_db

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

def _ensure_configured():
    """Checks if the init_auth function has been called."""
    if not settings.is_configured:
        raise ConfigurationError(
            "tsecure-auth has not been configured. "
            "Please call init_auth() at your application's startup."
        )

def get_cipher() -> TSTCipher:
    """
    Dependency that creates a TSTCipher instance from the global settings.
    """
    _ensure_configured()
    return TSTCipher(encryption_key=settings.ENCRYPTION_KEY)

def get_user_service(db: AsyncSession = Depends(get_db)) -> UserService:
    """Dependency to get the user service with a DB session."""
    return UserService(db)

def get_threat_service(db: AsyncSession = Depends(get_db)) -> ThreatService:
    """Dependency to get the threat service with a DB session."""
    return ThreatService(db)

def get_token_service() -> TokenService:
    """Dependency to get the token service."""
    return TokenService()

def get_current_token_payload(
    token: str = Depends(oauth2_scheme),
    cipher: TSTCipher = Depends(get_cipher),
    request: Request = None 
) -> dict:
    """
    A dependency that extracts, verifies, and returns the raw payload of a token.
    It now also performs context validation (IP and User-Agent).
    """
    _ensure_configured()
    try:
        payload = verify_token(token, cipher, expected_type="access")

        # Context Validation
        if settings.VALIDATE_IP:
            if payload.get('ip') != request.client.host:
                raise InvalidTokenError("Token used from a different IP address.")
        
        if settings.VALIDATE_USER_AGENT:
            if payload.get('ua') != request.headers.get("User-Agent"):
                raise InvalidTokenError("Token used from a different device/browser.")

        return payload
    except InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )

async def get_current_user(
    token_service: TokenService = Depends(get_token_service),
    payload: dict = Depends(get_current_token_payload),
) -> dict:
    """
    Dependency to get the current authenticated user from a TST payload,
    after ensuring the token has not been revoked.
    """
    jti = payload.get("jti")
    if not jti or token_service.is_blacklisted(jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id = payload.get("sub")
    if user_id is None:
        raise InvalidTokenError("Subject not found in token.")
    
    # This dependency now primarily validates the token's context and revocation status.
    # The user fetching is now done in the endpoint that needs the full user object.
    return payload
