from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import datetime, timedelta

from .core import Alert, Config, Event, analyze


@dataclass(frozen=True)
class Scenario:
    events: list[Event]
    malicious_ips: set[str]
    attacks: dict[str, str]


@dataclass(frozen=True)
class Score:
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float


def generate(seed: int = 42, normal_events: int = 500) -> Scenario:
    """Genera tráfico normal y cuatro ataques etiquetados y reproducibles."""
    rng = random.Random(seed)
    base = datetime(2026, 9, 2, 8)
    normal_ips = [f"10.0.0.{n}" for n in range(10, 40)]
    users = ["rafael", "andrea", "ventas", "soporte", "invitado"]
    paths = ["/", "/login", "/panel", "/productos", "/api/leads"]
    events: list[Event] = []

    for _ in range(normal_events):
        moment = base + timedelta(seconds=rng.randint(0, 12 * 3600))
        path = rng.choice(paths)
        # Un pequeño porcentaje de errores normales evita una simulación perfecta.
        result = "FAIL" if path == "/login" and rng.random() < 0.04 else "OK"
        events.append(Event(moment, rng.choice(normal_ips), rng.choice(users), result, path))

    attacks = {
        "203.0.113.10": "BRUTE_FORCE",
        "203.0.113.11": "USER_ENUMERATION",
        "203.0.113.12": "SENSITIVE_PATH_PROBE",
        "203.0.113.13": "OFF_HOURS_ADMIN",
    }
    for second in range(6):
        events.append(Event(base + timedelta(hours=1, seconds=second * 20),
                            "203.0.113.10", "admin", "FAIL", "/login"))
    for index, user in enumerate(["admin", "root", "test", "backup"]):
        events.append(Event(base + timedelta(hours=2, seconds=index * 30),
                            "203.0.113.11", user, "FAIL", "/login"))
    events.append(Event(base + timedelta(hours=3), "203.0.113.12",
                        "nobody", "FAIL", "/.env"))
    events.append(Event(base.replace(hour=3), "203.0.113.13",
                        "admin", "FAIL", "/wp-admin"))
    events.sort(key=lambda event: event.timestamp)
    return Scenario(events, set(attacks), attacks)


def evaluate(scenario: Scenario, alerts: list[Alert]) -> Score:
    detected = {alert.ip for alert in alerts}
    tp = len(detected & scenario.malicious_ips)
    fp = len(detected - scenario.malicious_ips)
    fn = len(scenario.malicious_ips - detected)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return Score(tp, fp, fn, precision, recall)


def run(seed: int = 42, normal_events: int = 500,
        config: Config | None = None) -> tuple[Scenario, list[Alert], Score]:
    scenario = generate(seed, normal_events)
    alerts = analyze(scenario.events, config)
    return scenario, alerts, evaluate(scenario, alerts)


def render_benchmark(scenario: Scenario, alerts: list[Alert], score: Score) -> str:
    detected = {alert.ip for alert in alerts}
    lines = [
        "RAEV GUARD — SIMULACIÓN CONTROLADA",
        "=" * 38,
        f"Eventos generados: {len(scenario.events)}",
        f"Ataques inyectados: {len(scenario.malicious_ips)}",
        f"IPs marcadas por el detector: {len(detected)}",
        "",
    ]
    for ip, attack in scenario.attacks.items():
        state = "DETECTADO" if ip in detected else "NO DETECTADO"
        lines.append(f"[{state}] {attack} — {ip}")
    lines += [
        "",
        f"Verdaderos positivos: {score.true_positives}",
        f"Falsos positivos:    {score.false_positives}",
        f"Falsos negativos:    {score.false_negatives}",
        f"Precisión:            {score.precision:.1%}",
        f"Cobertura (recall):   {score.recall:.1%}",
    ]
    return "\n".join(lines)

