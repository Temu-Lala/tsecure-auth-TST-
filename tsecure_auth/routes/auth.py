from fastapi import APIRouter, Depends, HTTPException, status, Body, Request
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from ..models.token import Token
from ..core.security import create_token, verify_token, TSTCipher
from ..dependencies import get_cipher, get_user_service, get_current_user, get_token_service, get_current_token_payload, get_threat_service
from ..core.config import settings
from ..services.user_service import UserService
from ..services.token_service import TokenService
from ..services.threat_service import ThreatService

def create_auth_router() -> APIRouter:
    """
    Factory function to create and return the configured authentication router.
    This allows routes to be defined with the dynamic models after configuration.
    """
    router = APIRouter()

    # Get the dynamic models from the settings
    UserCreateSchema = settings.UserCreateSchema
    UserPublicSchema = settings.UserPublicSchema

    @router.post("/register", response_model=UserPublicSchema, status_code=status.HTTP_201_CREATED)
    async def register_user(
        user_in: UserCreateSchema, # Directly use the dynamic schema
        user_service: UserService = Depends(get_user_service)
    ):
        user_dict = user_in.model_dump()
        identifier_field = next((f for f in settings.USER_MODEL_FIELDS if f != 'password'), 'email')
        
        if await user_service.get_user_by_attribute(identifier_field, user_dict.get(identifier_field)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"A user with this {identifier_field} already exists.",
            )
        
        created_user = await user_service.create_user(user_data=user_dict)
        
        # The user service now returns a dict, which can be directly validated
        return UserPublicSchema.model_validate(created_user)

    # All other routes go inside this factory as well...
    @router.post("/login", response_model=Token)
    async def login_for_access_token(
        request: Request,
        form_data: OAuth2PasswordRequestForm = Depends(),
        user_service: UserService = Depends(get_user_service),
        cipher: TSTCipher = Depends(get_cipher),
        threat_service: ThreatService = Depends(get_threat_service)
    ):
        # ... (rest of the login function remains the same)
        ip_address = request.client.host
        user_agent = request.headers.get("User-Agent")

        if await threat_service.is_brute_force_attack(ip_address):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many failed login attempts. Please try again later.",
            )

        identifier_field = next((f for f in settings.USER_MODEL_FIELDS if f not in ['password', 'id']), 'email')
        user = await user_service.authenticate_user(
            identifier_field=identifier_field,
            identifier_value=form_data.username, 
            password=form_data.password
        )
        if not user:
            await threat_service.log_event(
                event_type="login_fail", 
                ip_address=ip_address, 
                user_agent=user_agent,
                details=f"Attempted login for: {form_data.username}"
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect identifier or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        
        await threat_service.log_event(
            event_type="login_success",
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user['id']
        )

        # The 'user' variable is now a dictionary
        token_data = {
            field: user.get(field) for field in settings.TOKEN_PAYLOAD_FIELDS
        }
        if 'sub' not in token_data and 'id' in user:
            token_data['sub'] = str(user['id'])

        if settings.VALIDATE_IP:
            token_data['ip'] = request.client.host
        if settings.VALIDATE_USER_AGENT:
            token_data['ua'] = request.headers.get("User-Agent")

        access_token = create_token(
            token_type="access",
            data=token_data, 
            cipher=cipher,
            expires_delta=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
        refresh_token = create_token(
            token_type="refresh",
            data={"sub": str(user['id'])},  # <-- THE FINAL FIX IS HERE
            cipher=cipher,
            expires_delta=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )
        return {
            "access_token": access_token, 
            "refresh_token": refresh_token,
            "token_type": "bearer"
        }

    @router.post("/refresh", response_model=Token)
    async def refresh_access_token(
        refresh_token: str = Body(..., embed=True),
        cipher: TSTCipher = Depends(get_cipher),
        user_service: UserService = Depends(get_user_service)
    ):
        try:
            payload = verify_token(refresh_token, cipher, expected_type="refresh")
            user_id = int(payload.get("sub"))
            
            user = await user_service.get_user_by_id(user_id)
            if not user:
                raise HTTPException(status_code=401, detail="Invalid refresh token")
            
            # The 'user' variable is now a dictionary
            token_data = {
                field: user.get(field) for field in settings.TOKEN_PAYLOAD_FIELDS
            }
            if 'sub' not in token_data and 'id' in user:
                token_data['sub'] = str(user['id'])

            new_access_token = create_token(
                token_type="access",
                data=token_data,
                cipher=cipher,
                expires_delta=settings.ACCESS_TOKEN_EXPIRE_MINUTES
            )
            return {"access_token": new_access_token, "token_type": "bearer"}

        except Exception:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token",
            )

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    def logout(
        token_service: TokenService = Depends(get_token_service),
        payload: dict = Depends(get_current_token_payload)
    ):
        jti = payload.get("jti")
        if jti:
            token_service.add_to_blacklist(jti)
        return

    @router.get("/me", response_model=UserPublicSchema)
    async def read_users_me(
        current_user_payload: dict = Depends(get_current_user),
        user_service: UserService = Depends(get_user_service)
    ):
        user_id = int(current_user_payload.get("sub"))
        user = await user_service.get_user_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        return UserPublicSchema.model_validate(user)

    return router
