from __future__ import annotations
import argparse, sys
from pathlib import Path
from .core import Config, analyze, parse_text, render_csv, render_json, render_text, write_report

DEMO = """2026-09-02T09:12:01 192.168.1.20 rafael OK /panel
2026-09-02T09:18:17 203.0.113.45 admin FAIL /login
2026-09-02T09:18:20 203.0.113.45 root FAIL /login
2026-09-02T09:18:23 203.0.113.45 test FAIL /login
2026-09-02T09:18:27 203.0.113.45 guest FAIL /login
2026-09-02T09:18:31 203.0.113.45 rafael FAIL /login
2026-09-02T03:07:44 192.0.2.77 admin FAIL /wp-admin
2026-09-02T12:00:00 198.51.100.9 nobody FAIL /.env"""

def parser() -> argparse.ArgumentParser:
    app = argparse.ArgumentParser(prog="raev-guard",
        description="Analiza logs propios y genera alertas defensivas.")
    source = app.add_mutually_exclusive_group(required=False)
    source.add_argument("file", nargs="?", help="archivo de logs; usa - para stdin")
    source.add_argument("--demo", action="store_true", help="ejecuta datos de demostración")
    app.add_argument("--format", choices=("text", "json", "csv"), default="text")
    app.add_argument("--output", "-o", help="guarda el informe en un archivo")
    app.add_argument("--failed-threshold", type=int, default=5)
    app.add_argument("--window-minutes", type=int, default=10)
    app.add_argument("--strict", action="store_true")
    return app

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    if args.failed_threshold < 1 or args.window_minutes < 1:
        parser().error("los umbrales deben ser mayores que cero")
    if args.demo:
        source = DEMO
    elif args.file == "-":
        source = sys.stdin.read()
    elif args.file:
        try:
            source = Path(args.file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"Error al leer {args.file}: {exc}", file=sys.stderr)
            return 2
    else:
        parser().print_help()
        return 2
    try:
        events, errors = parse_text(source, strict=args.strict)
    except ValueError as exc:
        print(f"Error de formato: {exc}", file=sys.stderr)
        return 2
    alerts = analyze(events, Config(failed_threshold=args.failed_threshold,
                                    window_minutes=args.window_minutes))
    content = {"text": render_text(alerts, errors), "json": render_json(alerts, errors),
               "csv": render_csv(alerts)}[args.format]
    write_report(content, args.output)
    return 1 if alerts else 0

if __name__ == "__main__":
    raise SystemExit(main())

