import os
import sys
import pytest
import pytest_asyncio

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from typing import AsyncGenerator
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession

# Configure test environment variables before importing app
os.environ["ENVIRONMENT"] = "testing"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./test_database.db"
os.environ["REDIS_URL"] = "redis://localhost:6379/1"

from app.core.config import settings
settings.DATABASE_URL = "sqlite+aiosqlite:///./test_database.db"

from app.domain.models.base import Base
import app.domain.models  # ensure models are registered
from app.core.database import get_db
from app.main import app

test_engine = create_async_engine(
    "sqlite+aiosqlite:///./test_database.db",
    echo=False,
    connect_args={"check_same_thread": False},
)

TestAsyncSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db():
    """Initializes tables before running tests and tears them down after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    if os.path.exists("./test_database.db"):
        try:
            os.remove("./test_database.db")
        except Exception:
            pass


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Provides a transactional database session for each test."""
    async with TestAsyncSessionLocal() as session:
        yield session


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Provides an AsyncClient bound to the FastAPI application."""
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

    app.dependency_overrides.clear()
