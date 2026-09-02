# RAEV Guard

Analizador defensivo de registros de autenticación escrito en Python. Detecta
ráfagas de fallos, enumeración de usuarios, accesos administrativos fuera de
horario y sondeos de archivos sensibles.

Úsalo únicamente con registros propios o autorizados. No bloquea tráfico ni
sustituye un SIEM profesional.

## Requisitos

Python 3.10 o posterior. No tiene dependencias externas.

## Inicio rápido

~~~bash
python -m venv .venv
python -m pip install -e .
raev-guard --demo
~~~

El código de salida es 1 cuando hay alertas y 0 cuando no encuentra ninguna.

## Formato

Cada línea contiene fecha ISO, IP, usuario, resultado y ruta:

~~~text
2026-09-02T09:18:17 203.0.113.45 admin FAIL /login
~~~

El resultado admite OK o FAIL. Se ignoran líneas vacías y comentarios.

## Ejemplos

~~~bash
raev-guard examples/access.log
raev-guard examples/access.log --format json
raev-guard examples/access.log --format csv --output informe.csv
raev-guard examples/access.log --failed-threshold 8 --window-minutes 15
~~~

## Reglas

| Regla | Nivel | Detección |
|---|---|---|
| BRUTE_FORCE | Alto | Ráfaga de fallos desde una IP |
| USER_ENUMERATION | Medio | Una IP prueba múltiples usuarios |
| OFF_HOURS_ADMIN | Medio | Acceso administrativo de madrugada |
| SENSITIVE_PATH_PROBE | Alto | Petición a rutas como /.env |

## Pruebas

~~~bash
python -m unittest discover -s tests -v
~~~

La versión 1.0 usa un formato educativo normalizado. El siguiente paso puede
añadir adaptadores para Nginx, Apache, SSH y aplicaciones web.

