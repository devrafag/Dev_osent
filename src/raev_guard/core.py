from __future__ import annotations
import csv, io, json
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from pathlib import Path

@dataclass(frozen=True)
class Event:
    timestamp: datetime
    ip: str
    username: str
    result: str
    path: str

@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    ip: str
    reason: str
    first_seen: str
    last_seen: str
    evidence_count: int

@dataclass
class Config:
    failed_threshold: int = 5
    window_minutes: int = 10
    distinct_users_threshold: int = 3
    slow_failed_threshold: int = 8
    slow_window_hours: int = 24
    distributed_ip_threshold: int = 6
    distributed_window_minutes: int = 10
    unusual_start_hour: int = 0
    unusual_end_hour: int = 6
    admin_paths: tuple[str, ...] = ("/admin", "/wp-admin", "/panel")
    risky_paths: tuple[str, ...] = ("/.env", "/wp-config.php", "/phpmyadmin", "/server-status")

def parse_line(line: str, line_number: int = 0) -> Event:
    parts = line.split()
    if len(parts) != 5:
        raise ValueError(f"Línea {line_number}: se esperaban 5 campos y hay {len(parts)}")
    timestamp, ip, username, result, path = parts
    result = result.upper()
    if result not in {"OK", "FAIL"}:
        raise ValueError(f"Línea {line_number}: resultado debe ser OK o FAIL")
    try:
        parsed_time = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"Línea {line_number}: fecha ISO 8601 no válida") from exc
    if not path.startswith("/"):
        raise ValueError(f"Línea {line_number}: la ruta debe empezar por /")
    return Event(parsed_time, ip, username, result, path)

def parse_text(text: str, strict: bool = False) -> tuple[list[Event], list[str]]:
    events, errors = [], []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            events.append(parse_line(line, number))
        except ValueError as exc:
            if strict:
                raise
            errors.append(str(exc))
    events.sort(key=lambda event: event.timestamp)
    return events, errors

def _alert(severity: str, rule: str, ip: str, reason: str, events: list[Event]) -> Alert:
    return Alert(severity, rule, ip, reason, events[0].timestamp.isoformat(),
                 events[-1].timestamp.isoformat(), len(events))

def analyze(events: list[Event], config: Config | None = None) -> list[Alert]:
    cfg = config or Config()
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        by_ip[event.ip].append(event)
    alerts: list[Alert] = []
    for ip, ip_events in by_ip.items():
        failures = [event for event in ip_events if event.result == "FAIL"]
        left = 0
        for right, event in enumerate(failures):
            while event.timestamp - failures[left].timestamp > timedelta(minutes=cfg.window_minutes):
                left += 1
            window = failures[left:right + 1]
            if len(window) == cfg.failed_threshold:
                alerts.append(_alert("HIGH", "BRUTE_FORCE", ip,
                    f"{len(window)} fallos en {cfg.window_minutes} minutos", window))
        # Segundo horizonte: descubre ataques deliberadamente lentos.
        failures_by_user: dict[str, list[Event]] = defaultdict(list)
        for failure in failures:
            failures_by_user[failure.username].append(failure)
        for username, user_failures in failures_by_user.items():
            left = 0
            for right, event in enumerate(user_failures):
                while event.timestamp - user_failures[left].timestamp > timedelta(
                        hours=cfg.slow_window_hours):
                    left += 1
                slow_window = user_failures[left:right + 1]
                if len(slow_window) == cfg.slow_failed_threshold:
                    alerts.append(_alert("MEDIUM", "SLOW_BRUTE_FORCE", ip,
                        f"{len(slow_window)} fallos para {username} en "
                        f"{cfg.slow_window_hours} horas", slow_window))

        # Enumeración exige usuarios distintos dentro de la ventana rápida.
        for left, start in enumerate(failures):
            window = [event for event in failures[left:]
                      if event.timestamp - start.timestamp <= timedelta(
                          minutes=cfg.window_minutes)]
            users = {event.username for event in window}
            if len(users) >= cfg.distinct_users_threshold:
                alerts.append(_alert("MEDIUM", "USER_ENUMERATION", ip,
                    f"Probó {len(users)} usuarios distintos en "
                    f"{cfg.window_minutes} minutos", window))
                break
        off_hour = [event for event in ip_events
                    if cfg.unusual_start_hour <= event.timestamp.hour < cfg.unusual_end_hour
                    and event.path.lower() in cfg.admin_paths]
        if off_hour:
            alerts.append(_alert("MEDIUM", "OFF_HOURS_ADMIN", ip,
                "Acceso administrativo en horario inusual", off_hour))
        # Ignora parámetros y fragmentos para que /.env?cache=123 siga siendo /.env.
        risky = [event for event in ip_events
                 if event.path.lower().split("?", 1)[0].split("#", 1)[0] in cfg.risky_paths]
        if risky:
            alerts.append(_alert("HIGH", "SENSITIVE_PATH_PROBE", ip,
                f"Sondeo de ruta sensible: {risky[0].path}", risky))

    # Correlación transversal: varias IP atacan el mismo usuario en poco tiempo.
    failures_by_username: dict[str, list[Event]] = defaultdict(list)
    for event in events:
        if event.result == "FAIL":
            failures_by_username[event.username].append(event)
    distributed_ips_already_alerted: set[tuple[str, str]] = set()
    for username, user_failures in failures_by_username.items():
        left = 0
        for right, event in enumerate(user_failures):
            while event.timestamp - user_failures[left].timestamp > timedelta(
                    minutes=cfg.distributed_window_minutes):
                left += 1
            window = user_failures[left:right + 1]
            ips = {item.ip for item in window}
            if len(ips) >= cfg.distributed_ip_threshold:
                for attacker_ip in sorted(ips):
                    key = (username, attacker_ip)
                    if key in distributed_ips_already_alerted:
                        continue
                    evidence = [item for item in window if item.ip == attacker_ip]
                    alerts.append(_alert(
                        "HIGH", "DISTRIBUTED_CREDENTIAL_ATTACK", attacker_ip,
                        f"{len(ips)} IP atacaron al usuario {username} en "
                        f"{cfg.distributed_window_minutes} minutos", evidence))
                    distributed_ips_already_alerted.add(key)
    rank = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(alerts, key=lambda item: (rank[item.severity], item.first_seen, item.ip))

def render_text(alerts: list[Alert], errors: list[str] | None = None) -> str:
    lines = ["RAEV GUARD — INFORME DEFENSIVO", "=" * 33]
    if not alerts:
        lines.append("Sin alertas.")
    for index, alert in enumerate(alerts, 1):
        lines += [f"{index}. [{alert.severity}] {alert.rule} — {alert.ip}",
                  f"   {alert.reason}",
                  f"   Evidencias: {alert.evidence_count} | {alert.first_seen} → {alert.last_seen}"]
    if errors:
        lines += ["", f"Líneas ignoradas por formato incorrecto: {len(errors)}"]
        lines += [f"  - {error}" for error in errors[:10]]
    lines.append(f"\nTotal: {len(alerts)} alertas")
    return "\n".join(lines)

def render_json(alerts: list[Alert], errors: list[str] | None = None) -> str:
    return json.dumps({"alerts": [asdict(a) for a in alerts], "parse_errors": errors or []},
                      ensure_ascii=False, indent=2)

def render_csv(alerts: list[Alert]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=Alert.__dataclass_fields__.keys())
    writer.writeheader()
    writer.writerows(asdict(alert) for alert in alerts)
    return output.getvalue()

def write_report(content: str, destination: str | None) -> None:
    if destination:
        Path(destination).write_text(content, encoding="utf-8")
    else:
        print(content)
