from __future__ import annotations

import hashlib
import secrets
from collections import deque
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .core import Event, analyze


_salt = secrets.token_bytes(16)
_events: deque[Event] = deque(maxlen=250)


def _source_id(ip: str) -> str:
    digest = hashlib.sha256(_salt + ip.encode()).hexdigest()[:10]
    return f"src-{digest}"


def clear_honeypot() -> dict:
    _events.clear()
    return honeypot_snapshot()


def simulate_honeypot(kind: str) -> dict:
    now = datetime.now(timezone.utc)
    scenarios: dict[str, list[Event]] = {
        "brute-force": [
            Event(now + timedelta(seconds=i * 8), "198.51.100.24", "admin", "FAIL", "/decoy/login")
            for i in range(7)
        ],
        "user-enumeration": [
            Event(now + timedelta(seconds=i * 12), "203.0.113.18", user, "FAIL", "/decoy/login")
            for i, user in enumerate(("admin", "root", "soporte", "director", "backup"))
        ],
        "sensitive-scan": [
            Event(now + timedelta(seconds=i * 4), "192.0.2.71", "guest", "FAIL", path)
            for i, path in enumerate(("/.env", "/wp-config.php", "/phpmyadmin", "/server-status"))
        ],
        "slow-attack": [
            Event(now + timedelta(hours=i * 2), "203.0.113.90", "admin", "FAIL", "/decoy/login")
            for i in range(8)
        ],
        "normal-visit": [
            Event(now, "192.0.2.10", "visitor", "OK", "/decoy")
        ],
    }
    if kind not in scenarios:
        raise ValueError("Escenario de honeypot desconocido")
    _events.extend(scenarios[kind])
    return honeypot_snapshot(kind)


def honeypot_snapshot(last_scenario: str = "") -> dict:
    events = list(_events)
    alerts = analyze(events)
    safe_events = [
        {
            "time": event.timestamp.strftime("%H:%M:%S"),
            "source": _source_id(event.ip),
            "username": event.username,
            "result": event.result,
            "path": event.path,
        }
        for event in reversed(events[-30:])
    ]
    safe_alerts = [
        {
            **asdict(alert),
            "ip": _source_id(alert.ip),
        }
        for alert in alerts[-20:]
    ]
    return {
        "events": safe_events,
        "alerts": safe_alerts,
        "event_count": len(events),
        "alert_count": len(alerts),
        "sources": len({_source_id(event.ip) for event in events}),
        "last_scenario": last_scenario,
        "stores_passwords": False,
        "stores_full_ips": False,
    }
