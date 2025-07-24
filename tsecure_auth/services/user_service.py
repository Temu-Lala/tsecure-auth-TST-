from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from passlib.context import CryptContext
from typing import Dict, Optional, Any
from ..models.db_models import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserService:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    def _user_to_dict(self, user: User) -> Optional[Dict[str, Any]]:
        """Converts a User model to a dictionary, safely."""
        if not user:
            return None
        # This combines the model's ID with its flexible attributes field
        return {"id": user.id, **user.attributes}

    async def get_user_by_attribute(self, field: str, value: Any) -> Optional[Dict[str, Any]]:
        """Finds a user and returns them as a dictionary."""
        stmt = select(User).where(User.attributes[field].as_string() == str(value))
        result = await self.db.execute(stmt)
        user = result.scalars().first()
        return self._user_to_dict(user)

    async def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Finds a user by ID and returns them as a dictionary."""
        user = await self.db.get(User, user_id)
        return self._user_to_dict(user)

    async def create_user(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Creates a user and returns them as a dictionary."""
        user_attributes = user_data.copy()
        hashed_password = pwd_context.hash(user_attributes.pop('password'))
        
        db_user = User(
            hashed_password=hashed_password,
            attributes=user_attributes
        )
        
        self.db.add(db_user)
        await self.db.commit()
        await self.db.refresh(db_user)
        return self._user_to_dict(db_user)

    async def authenticate_user(self, identifier_field: str, identifier_value: Any, password: str) -> Optional[Dict[str, Any]]:
        """Authenticates a user and returns them as a dictionary."""
        stmt = select(User).where(User.attributes[identifier_field].as_string() == str(identifier_value))
        result = await self.db.execute(stmt)
        user = result.scalars().first()

        if not user or not pwd_context.verify(password, user.hashed_password):
            return None
        return self._user_to_dict(user) 