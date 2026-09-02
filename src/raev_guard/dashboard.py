from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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
<footer>Laboratorio local · No realiza conexiones a objetivos externos</footer>
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
    def do_GET(self) -> None:
        parsed = urlparse(self.path)
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
    args = parser.parse_args(argv)
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

