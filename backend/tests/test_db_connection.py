import uuid
import pytest
from sqlalchemy import text, select
from sqlalchemy.ext.asyncio import AsyncSession
from app.domain.models.users import User
from app.domain.models.logs import RawLog


@pytest.mark.asyncio
async def test_database_connection_and_raw_query(db_session: AsyncSession):
    """Verify database connection can execute raw SQL."""
    result = await db_session.execute(text("SELECT 1"))
    assert result.scalar() == 1


@pytest.mark.asyncio
async def test_database_crud_operations(db_session: AsyncSession):
    """Verify creating and retrieving entities with UUID and JSONB/JSON fields."""
    user_id = uuid.uuid4()
    test_user = User(
        id=user_id,
        email="test.analyst@secplatform.local",
        hashed_password="hashed_dev_password",
        full_name="Test Analyst",
        role="L1_ANALYST",
    )
    db_session.add(test_user)
    await db_session.commit()

    # Query back
    result = await db_session.execute(select(User).where(User.id == user_id))
    retrieved = result.scalars().first()
    assert retrieved is not None
    assert retrieved.email == "test.analyst@secplatform.local"
    assert retrieved.role == "L1_ANALYST"

    # Insert RawLog with JSON payload
    raw_log = RawLog(
        id=uuid.uuid4(),
        source_system="TestAzureActivity",
        raw_payload={"test_key": "test_value", "nested": {"num": 42}},
    )
    db_session.add(raw_log)
    await db_session.commit()

    result = await db_session.execute(select(RawLog).where(RawLog.id == raw_log.id))
    retrieved_log = result.scalars().first()
    assert retrieved_log is not None
    assert retrieved_log.raw_payload["nested"]["num"] == 42
