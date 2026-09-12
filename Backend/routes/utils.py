from datetime import datetime, timezone

from fastapi import HTTPException, status


def validate_date_range(
    start_time: datetime | None,
    end_time: datetime | None,
) -> None:
    if start_time is None or end_time is None:
        return

    normalized_start = (
        start_time.replace(tzinfo=timezone.utc)
        if start_time.tzinfo is None
        else start_time.astimezone(timezone.utc)
    )
    normalized_end = (
        end_time.replace(tzinfo=timezone.utc)
        if end_time.tzinfo is None
        else end_time.astimezone(timezone.utc)
    )
    if normalized_start > normalized_end:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="start_time must be earlier than or equal to end_time",
        )
