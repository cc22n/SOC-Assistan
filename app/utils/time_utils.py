from datetime import datetime, timezone


def utcnow() -> datetime:
    """UTC actual como datetime naive (compatible con columnas TIMESTAMP naive)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
