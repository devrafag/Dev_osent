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
raev-guard --simulate
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
| SLOW_BRUTE_FORCE | Medio | Muchos fallos espaciados durante 24 horas |
| USER_ENUMERATION | Medio | Una IP prueba múltiples usuarios |
| OFF_HOURS_ADMIN | Medio | Acceso administrativo de madrugada |
| SENSITIVE_PATH_PROBE | Alto | Petición a rutas como /.env |
| DISTRIBUTED_CREDENTIAL_ATTACK | Alto | Muchas IP atacan una cuenta en pocos minutos |

## Laboratorio simulado

El simulador genera cientos de accesos normales e inyecta cuatro incidentes
etiquetados. Como conocemos la respuesta correcta de antemano, mide:

- verdaderos positivos;
- falsos positivos;
- ataques no detectados;
- precisión y cobertura.

La simulación avanzada es reproducible y contiene fuerza bruta rápida y lenta,
enumeración de usuarios, acceso fuera de horario, rutas camufladas y un ataque
distribuido donde ocho IP hacen un solo intento contra la misma cuenta.

~~~bash
raev-guard --simulate
raev-guard --simulate --seed 99 --normal-events 5000
raev-guard --simulate --failed-threshold 8
~~~

### Resultados de referencia

| Tráfico normal | IP maliciosas | Detectadas | Falsos positivos | Precisión |
|---:|---:|---:|---:|---:|
| 500 | 14 | 14 | 0 | 100 % |
| 10.000 | 14 | 14 | 0 | 100 % |
| 50.000 | 14 | 14 | 10 | 58,3 % |

La caída con 50.000 eventos muestra una limitación real: cuando muchas
peticiones legítimas comparten pocas IP, los umbrales fijos generan ruido.
Estos resultados son del laboratorio incluido y no equivalen a rendimiento
garantizado sobre logs de producción.

## Panel gráfico

El panel usa exactamente el mismo motor de detección y funciona localmente, sin
enviar registros a internet ni instalar dependencias adicionales.

~~~bash
raev-guard-dashboard
~~~

Después abre http://127.0.0.1:8080. Desde el panel puedes cambiar la semilla y
el volumen, ejecutar el análisis y consultar incidentes, precisión, cobertura y
falsas alarmas.

## Pruebas

~~~bash
python -m unittest discover -s tests -v
~~~

La versión 1.0 usa un formato educativo normalizado. El siguiente paso puede
añadir adaptadores para Nginx, Apache, SSH y aplicaciones web.
