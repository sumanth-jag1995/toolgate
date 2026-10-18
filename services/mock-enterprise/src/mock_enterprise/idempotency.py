import hashlib
import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from mock_enterprise.models import IdempotencyRecord

CONFLICT_BODY = {"detail": "idempotency key reused with different payload"}


def hash_request(request_body: dict) -> str:
    canonical = json.dumps(request_body, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


async def run_idempotent(
    session: AsyncSession,
    *,
    client_id: str,
    key: UUID,
    request_body: dict,
    handler: Callable[[], Awaitable[tuple[int, dict]]],
) -> tuple[int, dict]:
    """Run ``handler`` at most once per (client_id, key).

    The record row is inserted first (ON CONFLICT DO NOTHING). A concurrent
    request with the same key blocks on the unique PK until the winner commits,
    then sees the conflict and replays the stored response. The handler's writes
    and the stored response commit in one transaction; if the handler raises, the
    transaction is rolled back so the key stays reusable.
    """
    key_str = str(key)
    request_hash = hash_request(request_body)
    inserted = await session.execute(
        insert(IdempotencyRecord)
        .values(
            client_id=client_id,
            key=key_str,
            request_hash=request_hash,
            response_json="",
            status_code=0,
            created_at=datetime.now(UTC),
        )
        .on_conflict_do_nothing(index_elements=["client_id", "key"])
        .returning(IdempotencyRecord.key)
    )
    if inserted.scalar_one_or_none() is None:
        # Lost the race (or a replay): the winner's row is committed and visible.
        record = (
            await session.execute(
                select(IdempotencyRecord).where(
                    IdempotencyRecord.client_id == client_id,
                    IdempotencyRecord.key == key_str,
                )
            )
        ).scalar_one()
        stored_hash, stored_status, stored_json = (
            record.request_hash,
            record.status_code,
            record.response_json,
        )
        await session.rollback()
        if stored_hash != request_hash:
            return 409, CONFLICT_BODY
        return stored_status, json.loads(stored_json)

    try:
        status_code, body = await handler()
        record = await session.get(IdempotencyRecord, (client_id, key_str))
        record.response_json = json.dumps(body)
        record.status_code = status_code
        await session.commit()
    except BaseException:
        await session.rollback()
        raise
    return status_code, body
