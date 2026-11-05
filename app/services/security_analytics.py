
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Audit


def get_security_analytics(db: Session):
    events = list(
        db.scalars(
            select(Audit).order_by(Audit.id.desc())
        )
    )

    total = len(events)
    allowed = sum(1 for event in events if event.allowed)
    denied = total - allowed

    actions = Counter(event.action for event in events)

    simulated = sum(
        1 for event in events if event.simulated
    )

    real = total - simulated

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(hours=24)

    recent_denials = defaultdict(list)

    for event in events:
        timestamp = event.created_at

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        if (
            not event.allowed
            and not event.simulated
            and timestamp >= window_start
        ):
            actor = (
                str(event.actor_id)
                if event.actor_id is not None
                else "ANONYMOUS"
            )

            recent_denials[actor].append(event)

    suspicious = []

    for actor, records in recent_denials.items():
        if len(records) >= 3:
            suspicious.append({
                "actor": actor,
                "denied_attempts": len(records),
                "severity": (
                    "HIGH" if len(records) >= 5 else "MEDIUM"
                ),
                "reason": (
                    "Repeated denied access attempts "
                    "within the last 24 hours"
                ),
            })

    suspicious.sort(
        key=lambda item: item["denied_attempts"],
        reverse=True,
    )

    return {
        "total_events": total,
        "allowed_events": allowed,
        "denied_events": denied,
        "denial_rate": (
            round((denied / total) * 100, 2)
            if total else 0.0
        ),
        "real_events": real,
        "simulated_events": simulated,
        "actions": dict(actions),
        "suspicious_activity": suspicious,
        "suspicious_actor_count": len(suspicious),
    }
