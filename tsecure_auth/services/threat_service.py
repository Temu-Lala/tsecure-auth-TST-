from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from datetime import datetime, timedelta
from ..models.db_models import SecurityEvent

class ThreatService:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def log_event(self, event_type: str, ip_address: str, user_agent: str, user_id: int = None, details: str = None):
        """Logs a security event to the database."""
        event = SecurityEvent(
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            user_id=user_id,
            details=details
        )
        self.db.add(event)
        await self.db.commit()

    async def is_brute_force_attack(self, ip_address: str, max_attempts: int = 5, window_minutes: int = 1) -> bool:
        """
        Checks if an IP address is making too many failed login attempts.
        """
        window_start_time = datetime.utcnow() - timedelta(minutes=window_minutes)
        
        stmt = select(func.count(SecurityEvent.id)).where(
            SecurityEvent.ip_address == ip_address,
            SecurityEvent.event_type == "login_fail",
            SecurityEvent.timestamp >= window_start_time
        )
        
        result = await self.db.execute(stmt)
        failed_attempts = result.scalar_one_or_none() or 0
        
        return failed_attempts >= max_attempts
