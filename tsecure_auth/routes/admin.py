from fastapi import APIRouter, Depends, Query
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from ..services.database import get_db
from ..dependencies import get_current_user
from ..models.db_models import SecurityEvent

router = APIRouter()

# Placeholder for a real admin check. In a real app, this would
# check if the user has an 'admin' role in their token or DB entry.
async def get_admin_user(user: dict = Depends(get_current_user)):
    # For now, any authenticated user is considered an "admin" for demonstration.
    return user

@router.get("/security-events", response_model=List[dict])
async def get_security_events(
    db: AsyncSession = Depends(get_db),
    admin_user: dict = Depends(get_admin_user),
    skip: int = 0,
    limit: int = Query(default=100, lte=1000),
):
    """
    Retrieve the latest security events.
    This endpoint would be used by an admin dashboard to monitor activity.
    Requires admin privileges.
    """
    stmt = select(SecurityEvent).order_by(SecurityEvent.timestamp.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    events = result.scalars().all()
    
    # Manually serialize to dictionaries
    return [
        {
            "id": event.id,
            "event_type": event.event_type,
            "user_id": event.user_id,
            "ip_address": event.ip_address,
            "user_agent": event.user_agent,
            "timestamp": event.timestamp,
            "details": event.details
        }
        for event in events
    ]
