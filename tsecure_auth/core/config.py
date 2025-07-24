from pydantic import BaseModel, create_model
from typing import List, Dict, Any, Type
from datetime import timedelta
from ..exceptions import ConfigurationError
from dotenv import load_dotenv
import os
load_dotenv()

class AuthSettings:
    """
    A singleton class to hold all authentication settings.
    This ensures that the configuration is set once and is accessible globally
    throughout the package.
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AuthSettings, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        self.is_configured = False
        self.ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "")
        self.ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
        self.REFRESH_TOKEN_EXPIRE_DAYS: int = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
        self.VALIDATE_IP: bool = os.getenv("VALIDATE_IP", "False") == "True"
        self.VALIDATE_USER_AGENT: bool = os.getenv("VALIDATE_USER_AGENT", "False") == "True"
        self.USER_MODEL_FIELDS: List[str] = os.getenv("USER_MODEL_FIELDS", "email,password").split(",")
        self.TOKEN_PAYLOAD_FIELDS: List[str] = os.getenv("TOKEN_PAYLOAD_FIELDS", "id,email").split(",")
        self.ADMIN_ROLE_NAME: str = os.getenv("ADMIN_ROLE_NAME", "admin")
        self.DEFAULT_USER_ROLE: str = os.getenv("DEFAULT_USER_ROLE", "user")
        
        # Dynamically created Pydantic models
        self.UserCreateSchema: Type[BaseModel] = None
        self.UserPublicSchema: Type[BaseModel] = None

    def configure(self, settings: Dict[str, Any]):
        # Allow explicit config to override env vars
        key = settings.get("ENCRYPTION_KEY", self.ENCRYPTION_KEY)
        if not key or len(key.encode('utf-8')) < 32:
            raise ConfigurationError("ENCRYPTION_KEY must be a string of at least 32 bytes.")
        self.ENCRYPTION_KEY = key
        
        self.ACCESS_TOKEN_EXPIRE_MINUTES = timedelta(minutes=settings.get("ACCESS_TOKEN_EXPIRE_MINUTES", self.ACCESS_TOKEN_EXPIRE_MINUTES))
        self.REFRESH_TOKEN_EXPIRE_DAYS = timedelta(days=settings.get("REFRESH_TOKEN_EXPIRE_DAYS", self.REFRESH_TOKEN_EXPIRE_DAYS))
        self.VALIDATE_IP = settings.get("VALIDATE_IP", self.VALIDATE_IP)
        self.VALIDATE_USER_AGENT = settings.get("VALIDATE_USER_AGENT", self.VALIDATE_USER_AGENT)
        self.USER_MODEL_FIELDS = settings.get("USER_MODEL_FIELDS", self.USER_MODEL_FIELDS)
        self.TOKEN_PAYLOAD_FIELDS = settings.get("TOKEN_PAYLOAD_FIELDS", self.TOKEN_PAYLOAD_FIELDS)
        self.ADMIN_ROLE_NAME = settings.get("ADMIN_ROLE_NAME", self.ADMIN_ROLE_NAME)
        self.DEFAULT_USER_ROLE = settings.get("DEFAULT_USER_ROLE", self.DEFAULT_USER_ROLE)
        
        self._create_dynamic_models()
        self.is_configured = True

    def _create_dynamic_models(self):
        """
        Dynamically creates Pydantic models based on the configured fields.
        This is the core of the customization feature.
        """
        # --- Create UserCreateSchema ---
        # All fields are required for registration.
        create_fields = {field: (str, ...) for field in self.USER_MODEL_FIELDS}
        self.UserCreateSchema = create_model('UserCreateSchema', **create_fields)

        # --- Create UserPublicSchema ---
        # The public model should not include the password.
        public_fields_list = [f for f in self.TOKEN_PAYLOAD_FIELDS if f != 'password']
        public_fields = {field: (Any, ...) for field in public_fields_list}
        # Add id field if not present
        if 'id' not in public_fields:
            public_fields['id'] = (int, ...)

        self.UserPublicSchema = create_model('UserPublicSchema', **public_fields)

# Global instance of the settings
settings = AuthSettings()

def init_auth(config: Dict[str, Any]):
    """
    Initializes the authentication system with user-defined settings.
    This must be called once at application startup.
    
    Example:
    init_auth({
        "ENCRYPTION_KEY": "your-super-secret-key-of-at-least-32-bytes",
        "USER_MODEL_FIELDS": ["username", "email", "password", "first_name"],
        "TOKEN_PAYLOAD_FIELDS": ["id", "username", "email"]
    })
    """
    settings.configure(config)
