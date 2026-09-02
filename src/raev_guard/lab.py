from __future__ import annotations

import re
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

from .core import Event, analyze


SCENARIOS = {
    "weak-password": {
        "title": "Contraseña débil",
        "lesson": "Una contraseña predecible facilita el acceso no autorizado.",
        "fix": "Usar contraseñas largas, MFA y bloqueo temporal de intentos.",
    },
    "brute-force": {
        "title": "Fuerza bruta",
        "lesson": "Muchos intentos consecutivos pueden revelar una cuenta desprotegida.",
        "fix": "Aplicar rate limiting, MFA y alertas por ventana temporal.",
    },
    "sql-injection": {
        "title": "Inyección SQL simulada",
        "lesson": "Concatenar entradas del usuario en una consulta puede alterar su significado.",
        "fix": "Usar consultas parametrizadas y cuentas de base de datos con mínimos permisos.",
    },
    "xss": {
        "title": "XSS simulado",
        "lesson": "Mostrar contenido sin escapar puede ejecutar código en el navegador de otra persona.",
        "fix": "Escapar la salida, sanear HTML y aplicar Content-Security-Policy.",
    },
}

SQL_PATTERN = re.compile(r"(?:\bunion\b.+\bselect\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|;\s*drop\b)", re.I)
XSS_PATTERN = re.compile(r"(?:<\s*script\b|onerror\s*=|javascript\s*:|<\s*svg\b)", re.I)


def run_lab_scenario(scenario: str, value: str, ip: str = "198.51.100.77") -> dict:
    if scenario not in SCENARIOS:
        raise ValueError("Escenario desconocido")
    if len(value) > 512:
        raise ValueError("La entrada supera el límite de 512 caracteres")

    now = datetime.now(timezone.utc)
    events: list[Event] = []
    detected = False
    rule = "SECURITY_REVIEW"
    evidence = "Entrada registrada para revisión."

    if scenario == "weak-password":
        detected = value.lower() in {"admin", "admin123", "password", "123456", "rafael"}
        rule = "WEAK_PASSWORD"
        evidence = "La contraseña aparece en una lista local de claves predecibles." if detected else "La clave no coincide con la lista de demostración."
    elif scenario == "brute-force":
        events = [Event(now + timedelta(seconds=i * 10), ip, "admin", "FAIL", "/lab/login") for i in range(5)]
        alerts = analyze(events)
        detected = any(alert.rule == "BRUTE_FORCE" for alert in alerts)
        rule = "BRUTE_FORCE"
        evidence = "RAEV Guard correlacionó 5 fallos en menos de 10 minutos."
    elif scenario == "sql-injection":
        detected = bool(SQL_PATTERN.search(value))
        rule = "SQL_INJECTION_PATTERN"
        evidence = "Patrón SQL sospechoso detectado; no se ejecutó ninguna consulta." if detected else "No se encontró el patrón de demostración."
    elif scenario == "xss":
        detected = bool(XSS_PATTERN.search(value))
        rule = "XSS_PATTERN"
        evidence = "Marcado HTML/JavaScript sospechoso detectado; se trató como texto." if detected else "No se encontró el patrón de demostración."

    info = SCENARIOS[scenario]
    return {
        "scenario": scenario,
        "title": info["title"],
        "lesson": info["lesson"],
        "fix": info["fix"],
        "detected": detected,
        "rule": rule,
        "evidence": evidence,
        "events": [asdict(event) for event in events],
        "safe": True,
    }
