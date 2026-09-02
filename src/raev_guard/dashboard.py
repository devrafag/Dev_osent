from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlparse

from .simulator import run


HTML = """<!doctype html>
<html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>RAEV Guard — Laboratorio</title>
<style>
:root{--bg:#080c10;--panel:#111820;--line:#26323d;--text:#edf4f5;--muted:#82919b;--green:#58e0b5;--red:#ff6577;--amber:#f3bc55}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 80% 0,#12332d 0,transparent 28%),var(--bg);color:var(--text);font-family:Inter,Arial,sans-serif}
main{max-width:1180px;margin:auto;padding:38px 22px}header{display:flex;justify-content:space-between;align-items:end;border-bottom:1px solid var(--line);padding-bottom:24px}
.brand{letter-spacing:.2em;color:var(--green);font-size:11px}h1{font:400 36px Georgia;margin:9px 0 6px}.subtitle{color:var(--muted);font-size:13px}
.controls{display:flex;gap:10px;flex-wrap:wrap}.field{background:var(--panel);border:1px solid var(--line);padding:9px 12px;border-radius:5px}.field label{display:block;color:var(--muted);font-size:8px;letter-spacing:.1em;margin-bottom:5px}.field input{width:90px;background:none;border:0;color:var(--text);font-weight:bold;outline:0}
button{border:0;border-radius:5px;background:var(--green);color:#06120e;padding:13px 18px;font-weight:800;cursor:pointer}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:22px 0}.card,.tablebox{background:var(--panel);border:1px solid var(--line);padding:18px}.card small{display:block;color:var(--muted);font-size:8px;letter-spacing:.11em}.card strong{display:block;font:400 28px Georgia;margin-top:10px}.good{color:var(--green)}.warn{color:var(--amber)}.grid{display:grid;grid-template-columns:1.3fr .7fr;gap:10px}.tablebox h2{font:400 20px Georgia;margin:0 0 15px}table{border-collapse:collapse;width:100%;font-size:11px}th{text-align:left;color:var(--muted);font-size:8px;letter-spacing:.1em;padding:10px;border-bottom:1px solid var(--line)}td{padding:11px 10px;border-bottom:1px solid #202b34}.pill{padding:4px 7px;border-radius:3px;background:#173a31;color:var(--green);font-size:8px}.bar{height:8px;background:#202c34;margin:10px 0}.bar i{display:block;height:100%;background:var(--green)}.note{color:var(--muted);font-size:11px;line-height:1.6}.loading{opacity:.55}footer{color:#586670;font-size:9px;padding:22px 0}
@media(max-width:760px){header{display:block}.controls{margin-top:20px}.metrics{grid-template-columns:repeat(2,1fr)}.grid{grid-template-columns:1fr}h1{font-size:29px}}
</style></head><body><main id="app">
<header><div><div class="brand">RAEV GUARD / DEFENSIVE LAB</div><h1>Simulación controlada</h1><div class="subtitle">Ataques etiquetados, detección medible y cero tráfico externo.</div></div>
<div class="controls"><div class="field"><label>SEMILLA</label><input id="seed" type="number" value="42"></div><div class="field"><label>TRÁFICO NORMAL</label><input id="events" type="number" value="10000" min="0" max="100000"></div><button onclick="simulate()">Ejecutar análisis →</button></div></header>
<section class="metrics"><div class="card"><small>EVENTOS</small><strong id="total">—</strong></div><div class="card"><small>IP MALICIOSAS</small><strong id="attacks">—</strong></div><div class="card"><small>DETECTADAS</small><strong id="tp" class="good">—</strong></div><div class="card"><small>FALSAS ALARMAS</small><strong id="fp">—</strong></div><div class="card"><small>PRECISIÓN</small><strong id="precision">—</strong></div></section>
<section class="grid"><div class="tablebox"><h2>Incidentes inyectados</h2><table><thead><tr><th>ESTADO</th><th>ATAQUE</th><th>IP</th></tr></thead><tbody id="rows"></tbody></table></div>
<div class="tablebox"><h2>Rendimiento</h2><small class="subtitle">COBERTURA</small><div class="bar"><i id="recallbar"></i></div><strong id="recall">—</strong><p class="note">La precisión baja cuando aparecen falsas alarmas. La cobertura baja cuando un ataque consigue pasar inadvertido.</p><p class="note" id="summary"></p></div></section>
<footer>Laboratorio local · No realiza conexiones a objetivos externos · <form method="post" action="/logout" style="display:inline"><button style="padding:5px 8px;background:#202c34;color:#82919b">Cerrar sesión</button></form></footer>
</main><script>
async function simulate(){
 const app=document.getElementById("app"); app.classList.add("loading");
 const seed=document.getElementById("seed").value; const events=document.getElementById("events").value;
 try{
  const response=await fetch("/api/simulate?seed="+encodeURIComponent(seed)+"&events="+encodeURIComponent(events));
  if(!response.ok) throw new Error("Parámetros no válidos");
  const data=await response.json();
  ["total","attacks","tp","fp"].forEach(function(id){document.getElementById(id).textContent=data[id]});
  document.getElementById("precision").textContent=(data.precision*100).toFixed(1)+"%";
  document.getElementById("recall").textContent=(data.recall*100).toFixed(1)+"%";
  document.getElementById("recallbar").style.width=(data.recall*100)+"%";
  document.getElementById("fp").className=data.fp?"warn":"good";
  document.getElementById("rows").innerHTML=data.incidents.map(function(x){
   return "<tr><td><span class=pill>"+(x.detected?"DETECTADO":"PERDIDO")+"</span></td><td>"+x.attack+"</td><td>"+x.ip+"</td></tr>"
  }).join("");
  document.getElementById("summary").textContent=data.fp===0?"Sin falsas alarmas en esta ejecución.":data.fp+" IP legítimas fueron marcadas. Conviene ajustar umbrales.";
 }catch(error){alert(error.message)}finally{app.classList.remove("loading")}
}
simulate();
</script></main></body></html>"""

LOGIN_HTML = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width"><title>Acceso — RAEV Guard</title>
<style>
:root{--bg:#080c10;--panel:#111820;--line:#26323d;--text:#edf4f5;--muted:#82919b;--green:#58e0b5}
*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at 70% 10%,#12332d 0,transparent 35%),var(--bg);color:var(--text);font-family:Arial,sans-serif}
main{width:min(390px,calc(100% - 32px));background:var(--panel);border:1px solid var(--line);padding:32px}.brand{color:var(--green);font-size:10px;letter-spacing:.2em}h1{font:400 29px Georgia;margin:13px 0 8px}p{color:var(--muted);font-size:12px;line-height:1.5;margin-bottom:24px}label{display:block;color:var(--muted);font-size:9px;letter-spacing:.1em;margin:14px 0 6px}input{width:100%;padding:12px;border:1px solid var(--line);border-radius:4px;background:#0b1117;color:var(--text);outline:0}input:focus{border-color:var(--green)}button{width:100%;margin-top:20px;padding:13px;border:0;border-radius:4px;background:var(--green);color:#06120e;font-weight:bold}.error{color:#ff7887;margin:0 0 12px}
</style></head><body><main><div class="brand">RAEV GUARD</div><h1>Acceso protegido</h1>
<p>Introduce tus credenciales para abrir el laboratorio defensivo.</p>
{error}<form method="post" action="/login"><label>USUARIO</label><input name="username" autocomplete="username" required>
<label>CONTRASEÑA</label><input name="password" type="password" autocomplete="current-password" required>
<button type="submit">Entrar →</button></form></main></body></html>"""

SESSION_COOKIE = "raev_session"
SESSION_SECONDS = 8 * 60 * 60
_attempts: dict[str, list[float]] = {}


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return base64.urlsafe_b64encode(salt).decode() + "." + base64.urlsafe_b64encode(digest).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_text, expected_text = encoded.split(".", 1)
        salt = base64.urlsafe_b64decode(salt_text)
        expected = base64.urlsafe_b64decode(expected_text)
        actual = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def create_session(username: str, secret: str, now: int | None = None) -> str:
    expires = (now or int(time.time())) + SESSION_SECONDS
    payload = base64.urlsafe_b64encode(f"{username}:{expires}".encode()).decode().rstrip("=")
    signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + signature


def verify_session(token: str, username: str, secret: str,
                   now: int | None = None) -> bool:
    try:
        payload, signature = token.split(".", 1)
        expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return False
        padded = payload + "=" * (-len(payload) % 4)
        stored_user, expires = base64.urlsafe_b64decode(padded).decode().rsplit(":", 1)
        return hmac.compare_digest(stored_user, username) and int(expires) >= (
            now or int(time.time()))
    except (ValueError, TypeError):
        return False


def login_allowed(ip: str, now: float | None = None) -> bool:
    current = now or time.time()
    recent = [attempt for attempt in _attempts.get(ip, [])
              if current - attempt < 15 * 60]
    _attempts[ip] = recent
    return len(recent) < 5


def record_failed_login(ip: str, now: float | None = None) -> None:
    _attempts.setdefault(ip, []).append(now or time.time())


def simulation_payload(seed: int, normal_events: int) -> dict:
    if normal_events < 0 or normal_events > 100_000:
        raise ValueError("events debe estar entre 0 y 100000")
    scenario, alerts, score = run(seed=seed, normal_events=normal_events)
    detected = {alert.ip for alert in alerts}
    return {
        "total": len(scenario.events),
        "attacks": len(scenario.malicious_ips),
        "tp": score.true_positives,
        "fp": score.false_positives,
        "fn": score.false_negatives,
        "precision": score.precision,
        "recall": score.recall,
        "incidents": [
            {"ip": ip, "attack": attack, "detected": ip in detected}
            for ip, attack in scenario.attacks.items()
        ],
        "alerts": [asdict(alert) for alert in alerts],
    }


class Handler(BaseHTTPRequestHandler):
    @property
    def username(self) -> str:
        return os.environ.get("RAEV_USERNAME", "")

    @property
    def secret(self) -> str:
        return os.environ.get("RAEV_SESSION_SECRET", "")

    def _authenticated(self) -> bool:
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get(SESSION_COOKIE)
        return bool(token and verify_session(
            token.value, self.username, self.secret))

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/login":
            if self._authenticated():
                self._redirect("/")
            else:
                self._login_page()
            return
        if not self._authenticated():
            if parsed.path.startswith("/api/"):
                self._send(401, b'{"error":"authentication required"}',
                           "application/json")
            else:
                self._redirect("/login")
            return
        if parsed.path == "/":
            self._send(200, HTML.encode(), "text/html; charset=utf-8")
            return
        if parsed.path == "/api/simulate":
            try:
                query = parse_qs(parsed.query)
                seed = int(query.get("seed", ["42"])[0])
                events = int(query.get("events", ["500"])[0])
                body = json.dumps(simulation_payload(seed, events),
                                  ensure_ascii=False).encode()
                self._send(200, body, "application/json")
            except (ValueError, TypeError) as exc:
                self._send(400, json.dumps({"error": str(exc)}).encode(),
                           "application/json")
            return
        self._send(404, b"Not found", "text/plain")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/logout":
            self.send_response(303)
            self.send_header("Location", "/login")
            self.send_header("Set-Cookie",
                             f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
            self.end_headers()
            return
        if parsed.path != "/login":
            self._send(404, b"Not found", "text/plain")
            return
        ip = self.client_address[0]
        if not login_allowed(ip):
            self._login_page("Demasiados intentos. Espera 15 minutos.", 429)
            return
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 4096)
        except ValueError:
            length = 0
        form = parse_qs(self.rfile.read(length).decode(errors="replace"))
        username = form.get("username", [""])[0]
        password = form.get("password", [""])[0]
        expected_hash = os.environ.get("RAEV_PASSWORD_HASH", "")
        valid = (hmac.compare_digest(username, self.username)
                 and verify_password(password, expected_hash))
        if not valid:
            record_failed_login(ip)
            self._login_page("Usuario o contraseña incorrectos.", 401)
            return
        token = create_session(self.username, self.secret)
        secure = (self.headers.get("X-Forwarded-Proto") == "https"
                  or os.environ.get("RAEV_COOKIE_SECURE") == "1")
        attributes = "; Path=/; Max-Age=28800; HttpOnly; SameSite=Strict"
        if secure:
            attributes += "; Secure"
        self.send_response(303)
        self.send_header("Location", "/")
        self.send_header("Set-Cookie", f"{SESSION_COOKIE}={token}{attributes}")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _login_page(self, error: str = "", status: int = 200) -> None:
        message = f'<p class="error">{error}</p>' if error else ""
        self._send(status, LOGIN_HTML.replace("{error}", message).encode(),
                   "text/html; charset=utf-8")

    def _redirect(self, location: str) -> None:
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Panel local de RAEV Guard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--generate-password-hash",
                        help="genera el hash que debes guardar como secreto")
    args = parser.parse_args(argv)
    if args.generate_password_hash:
        print(password_hash(args.generate_password_hash))
        return
    missing = [name for name in ("RAEV_USERNAME", "RAEV_PASSWORD_HASH",
                                  "RAEV_SESSION_SECRET")
               if not os.environ.get(name)]
    if missing:
        parser.error("faltan variables secretas: " + ", ".join(missing))
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"RAEV Guard disponible en http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
