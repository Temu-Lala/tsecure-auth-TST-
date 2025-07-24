from pydantic import BaseModel
from typing import Optional

class TokenPayload(BaseModel):
    """
    Defines the payload for the TST access token.
    'sub' (subject) will typically be the user's ID.
    """
    sub: str
    
class Token(BaseModel):
    """
    Represents the token that is returned to the client upon successful authentication.
    """
    access_token: str
    token_type: str = "bearer"
