from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv
import os
load_dotenv()

# --- PostgreSQL Connection String ---
# IMPORTANT: Replace these placeholders with your actual database credentials.
# Format: "postgresql+asyncpg://user:password@host:port/database"
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite+aiosqlite:///./test.db")

# To use this, you will need to install the 'asyncpg' driver:
# .venv/bin/pip install asyncpg

engine = create_async_engine(DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine, class_=AsyncSession
)

Base = declarative_base()

async def get_db() -> AsyncSession:
    """
    FastAPI dependency to get a database session.
    Ensures the session is properly closed after the request.
    """
    async with AsyncSessionLocal() as session:
        yield session
