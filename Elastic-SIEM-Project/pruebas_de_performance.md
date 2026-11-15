# Pruebas de performance (k6)

Las pruebas de `tests/unit/`, `tests/integration/` y `tests/interfaz/` verifican
que el panel **funciona**. Estas verifican **cuánto aguanta**: cuántos analistas
pueden tener el panel abierto a la vez, con qué latencia responde y dónde se rompe.
Usan [k6](https://grafana.com/docs/k6/) contra el sistema real levantado en Docker.

```bash
./scripts/pruebas_de_performance.sh            # humo (1 VU, 30 s)
./scripts/pruebas_de_performance.sh carga      # 20 VUs, 4 min
./scripts/pruebas_de_performance.sh estres     # sube hasta 150 VUs, 5 min
./scripts/pruebas_de_performance.sh pico       # salto de 5 a 100 VUs y recuperación
./scripts/pruebas_de_performance.sh login      # 1 login real por segundo, 1 min
```

No hay que instalar nada: k6 corre en un contenedor (`grafana/k6:1.3.0`, versión
fija) con la red del host, y le pega al panel en `127.0.0.1:5000`. El panel tiene
que estar levantado (`./scripts/start.sh` o `docker compose up -d gateway`).

## Qué se mide

Cada usuario virtual (VU) imita a un analista con el panel abierto. En cada vuelta:

1. **Abre el panel:** `GET /api/v1/me`, `/api/v1/incidents`, `/api/v1/decisions`
   y `/api/v1/memoria`.
2. **Abre un incidente al azar:** `GET /api/v1/incidents/<id>`.
3. **Verifica la cadena de auditoría**, solo en ~1 de cada 10 vueltas:
   `GET /api/v1/audit/verify`.
4. **Consulta la sonda de salud:** `GET /api/v1/healthz`.
5. **Lee 1-3 s** antes del refresco siguiente.

Cada pedido cruza el gateway y llega por HTTP al microservicio dueño del dato
(pipeline, audit o knowledge). Por eso se mide la malla entera, no solo Flask.
Cada endpoint tiene su propia métrica (`t_incidentes`, `t_memoria`, …), así que
el resumen muestra cuál es el cuello de botella.

**Qué no se hace, a propósito:**

- **No se registran decisiones** (`POST /api/v1/decision`): el registro de
  auditoría es inmutable y quedaría lleno de decisiones falsas.
- **No se hace login en cada vuelta.** Argon2id es caro a propósito, y el control
  anti fuerza bruta bloquearía al usuario. Se inicia sesión una sola vez en
  `setup()` y todos los VUs comparten esa cookie. El costo del login se mide
  aparte, con el perfil `login`. Cada login de ese perfil deja una entrada
  `login_exitoso` en `data/audit/accesos.jsonl`.

## Usuario

Por defecto se usa `k6-carga`, con rol **auditor**: ve todo y verifica la cadena,
pero no puede decidir. Si no existe, el script lo crea la primera vez con una
contraseña aleatoria. La contraseña queda en `.k6-credenciales`, con permisos
0600 y fuera de git. Para usar otro usuario: `K6_USUARIO=… K6_CLAVE=…
./scripts/pruebas_de_performance.sh`. Para darlo de baja:
`./scripts/siem.sh usuarios baja k6-carga`.

## Umbrales

Si un umbral no se cumple, k6 sale con código 99 y el script avisa.

| Métrica | Umbral |
|---------|--------|
| `http_req_failed` | < 1 % |
| `checks` (todo 200) | > 99 % |
| `t_incidentes`, `t_incidente`, `t_decisiones`, `t_memoria` | p95 < 500 ms |
| `t_me`, `t_salud` | p95 < 300 ms |
| `t_verificar_cadena` | p95 < 2 s |
| `t_login` (perfil `login`) | p95 < 2 s |

En `estres` y `pico`, que un umbral falle es el resultado buscado: muestra
**dónde** se rompe el panel. No es un error de la prueba.

## Resultados

Cada corrida deja dos archivos en `reportes/performance/<fecha>-<perfil>`:

- **`.html`:** el panel web de k6 exportado, con latencias, VUs, pedidos por
  segundo y errores en el tiempo. Se abre en el navegador.
- **`.json`:** el resumen con todas las métricas (`--summary-export`).

### Línea de base (2026-11-12, notebook de desarrollo, stack completo + Elastic)

| Perfil | VUs | Pedidos | Req/s | Errores | p95 incidentes | p95 `/me` | Umbrales |
|--------|-----|---------|-------|---------|----------------|-----------|----------|
| humo | 1 | 95 | 3 | 0 % | 11 ms | 4 ms | ✅ |
| carga | 20 | 12.594 | 52 | 0 % | 21 ms | 9 ms | ✅ |
| estres | hasta 150 | 42.835 | 142 | 0 % | 351 ms | 319 ms | ⚠️ `t_me` y `t_salud` > 300 ms |
| pico (antes del arreglo) | 5 → 100 → 5 | 16.194 | 95 | 0,006 % (1 × 503) | 239 ms | 201 ms | ✅ |
| pico (después del arreglo) | 5 → 100 → 5 | 16.072 | 94 | 0 % | 251 ms | 211 ms | ✅ |
| login | 1 login/s | 62 | 1 | 0 % | — | — | ✅ p95 `t_login` 82 ms |

En `pico`, el error del primer intento no viene de la carga: es la carrera que
se explica en «Lo que encontró k6». En `login`, el p95 de 82 ms incluye Argon2id
y el registro del acceso en la auditoría.

**Lectura.** Con 20 analistas simultáneos (4 veces un SOC chico), todo responde
en menos de 25 ms. Con 150 VUs no hay ni un error, pero la latencia sube de
forma pareja en todos los endpoints. Hasta `/me` y `/healthz`, que no hacen casi
nada, tardan lo mismo que el resto. Eso indica que el cuello de botella es la
cola del gateway: gunicorn corre con 1 worker y 8 threads. Durante un perfil
`pico` (100 VUs), `docker stats` cada 3 s dio para el gateway un máximo de 154 %
de CPU (promedio 56 %). En los servicios de atrás, los máximos fueron: auth 68 %,
pipeline 49 %, knowledge 36 % y audit 32 %. El gateway es el más cargado, lo
que apoya la hipótesis. Si hiciera falta más capacidad, la palanca es subir los
workers del gateway en su `Dockerfile`.

### Lo que encontró k6 (2026-11-12)

En el primer perfil `pico`, 1 de 16.194 pedidos devolvió **503**. No era un
problema de carga: el ciclo automático del pipeline reescribía
`siem_incidents.json` justo cuando el gateway lo leía, y la lectura encontró
el JSON a medio escribir. `write_json` (`libs/siem_lib.py`) truncaba el archivo
y lo reescribía en el mismo lugar. Ahora escribe un temporal y lo reemplaza
con `os.replace`, que es atómico. La prueba
`test_write_json_es_atomico_para_un_lector_concurrente` reproduce la carrera:
falla con el código anterior. El arreglo vale también para la memoria del
agente (`knowledge`) y la captura del collector, que usan la misma función.

## Archivos

- `tests/performance/neuraldefender.js`: el escenario, los perfiles y los umbrales.
- `scripts/pruebas_de_performance.sh`: corre k6 en Docker, crea el usuario y guarda los reportes.
