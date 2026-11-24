# Informe de Pruebas de Rendimiento de APIs (SDET Performance Test Report)

**Proyecto**: NeuralDefender - Elastic-SIEM-Project
**Fecha de generación del informe**: 2026-11-24 12:44:11
**Fecha y hora de la corrida**: 2026-11-24 12:01:32 a 2026-11-24 12:39:07
**Herramienta**: Grafana k6 (`grafana/k6:1.3.0`)
**Ambiente**: malla aislada de los 8 servicios (`http://127.0.0.1:18080`): 100 incidentes, 20 analistas y 1.400 decisiones sembradas (7 días de uso a 200 por día), sin ciclo del pipeline
**Autor**: Equipo NeuralDefender-IyCS

---

## 1. Resumen Ejecutivo (Executive Summary)

Cada grupo de endpoints se prueba con **su propio perfil de uso**, no con una carga única. La **carga** corre los 5 grupos en paralelo, cada uno con su tasa real; el **estrés** corre una vez por grupo, con niveles propios y, en cada nivel, una subida corta y una meseta sostenida de 60 s. El p95 de cada meseta se mide por separado.

| Corrida | Inicio | Duración real | Código de k6 | Umbrales incumplidos | Nota |
| :--- | :--- | :---: | :---: | :--- | :--- |
| Carga (todos los grupos) | 2026-11-24 12:29:22 | 4:43 | 0 | ninguno | Repetición: la primera corrida de este escenario tuvo conexiones rechazadas al inicio (carga: 4; auditoría: 1) que no se reprodujeron; ver corrida_previa_con_rechazos/ |
| Estrés: Lecturas del panel | 2026-11-24 12:01:32 | 3:52 | 0 | ninguno | - |
| Estrés: Registro de decisiones | 2026-11-24 12:05:31 | 3:54 | 0 | ninguno | - |
| Estrés: Inicio de sesión | 2026-11-24 12:09:31 | 3:39 | 99 | `http_req_duration{grupo:login,endpoint:login,fase:meseta_100} p(95)<2000`; `http_req_duration{grupo:login,endpoint:login,fase:meseta_50} p(95)<2000` | - |
| Estrés: Auditoría (informes y verificación) | 2026-11-24 12:34:14 | 4:53 | 0 | ninguno | Repetición: la primera corrida de este escenario tuvo conexiones rechazadas al inicio (carga: 4; auditoría: 1) que no se reprodujeron; ver corrida_previa_con_rechazos/ |

Duración total medida: **21:01** (suma de las corridas de k6, sin contar el reinicio de la malla entre ellas). Código de k6: 0 significa que se cumplieron todos los umbrales; 99, que alguno no.

- **Carga**: 1,191 peticiones, 4.41 por segundo, checks 100.00% (2,246 de 2,246). Umbrales por meseta: **todos cumplidos** (14 de 14).
- **Estrés de lecturas del panel**: sin punto de quiebre hasta 150 analistas equivalentes.
- **Estrés de registro de decisiones**: sin punto de quiebre hasta 150 analistas equivalentes.
- **Estrés de inicio de sesión**: primer incumplimiento en la meseta de **50 inicios de sesión simultáneos**.
- **Estrés de auditoría (informes y verificación)**: sin punto de quiebre hasta 10 pedidos concurrentes.

---

## 2. Configuración del Escenario de Carga (Workload Configuration)

### 2.1. Característica ISO/IEC 25010 evaluada

Se evalúa la característica **Eficiencia en el desempeño** (*Performance efficiency*), con tres subcaracterísticas:

| Subcaracterística | Qué mide | Requisitos de la ERS | Dónde se verifica |
| :--- | :--- | :--- | :--- |
| **Comportamiento temporal** (*Time behaviour*) | Tiempos de respuesta | RNF-RD-01 (listado de incidentes p95 < 2 s), RNF-RD-04 (registro de decisión p95 < 500 ms) | Carga |
| **Capacidad** (*Capacity*) | Límites máximos que soporta el sistema | RNF-RD-09 (hasta 100 analistas, lecturas p95 < 500 ms, menos de 1 % de fallos) | Estrés de lecturas |
| **Utilización de recursos** (*Resource utilization*) | Consumo de recursos | RNF-RD-02, RNF-RD-05, RNF-RD-08 | No se evalúa en este entregable |

### 2.2. Perfil de uso por endpoint (con 20 analistas)

| Endpoint | Quién lo usa | Frecuencia por usuario | Peticiones por segundo | Justificación |
| :--- | :--- | :--- | :---: | :--- |
| incidents, decisions y memoria (cada uno) | Los 3 roles | 1 cada 15 s con el panel abierto | 1,33 + 0,14 (recargas tras decidir) | app.js:1308 (refresco de 15 s, RF-SUP-07); 20 analistas / 15 s |
| POST /api/v1/decision | Analista | 200 por día en un turno de 8 h | 0,14 | ERS línea 621 (200 decisiones diarias); 20 x 200 / 8 h = 500 por hora |
| POST /api/v1/login | Todos | 1 por sesión (máx. 8 h); ráfaga de inicio de turno | 0,0007 de promedio; ráfaga de 20 simultáneos | sesion_web.py: sesión máxima de 8 h; supuesto de ráfaga |
| GET /api/v1/reportes | Auditor y analista | 1 por analista por hora (supuesto) | 0,0056 | Supuesto declarado en el plan: ERS sin frecuencia |
| GET /api/v1/audit/verify | Auditor | 1 cada 10 min con 2 auditores (supuesto) | 0,0033 | Supuesto declarado en el plan; solo vía API. En la carga se fuerza 1 verificación en la meseta |
| GET /api/v1/healthz | Contenedor (sonda) | 1 cada 10 s | 0,1 | docker-compose.yml:461 (intervalo del healthcheck) |

**Supuestos declarados:** refresco de 15 s (el del código; la ERS, línea 720, modela 1 a 3 s, una diferencia que se registra); roles analista, administrador y auditor (no hay supervisor); informes a razón de 1 por analista por hora; la ráfaga de inicio de turno y la frecuencia de la verificación de la cadena son supuestos del equipo.

### 2.3. Entorno y datos

| Elemento | Valor |
| :--- | :--- |
| Sistema bajo prueba | Gateway (`/api/v1`) y los servicios internos que invoca, en la malla aislada (`malla.sh`) |
| Datos | `--incidentes 100 --analistas 20 --decisiones 1400`: 1.400 decisiones sembradas con cadena de hashes válida, equivalentes a 7 días de uso a 200 por día (≈ 760 KB de `GET /decisions`) |
| Estado inicial | La malla se reinicia antes de CADA corrida |
| Autenticación | Inicio de sesión real de cada usuario virtual, con su cookie y su token CSRF conservados |
| Generador | k6 en contenedor con red del host, en el mismo equipo (16 CPU) |

### 2.4. Escenarios

**Carga** (los 5 grupos en paralelo, 4:30 cada uno): lecturas (`ramping-arrival-rate`, 20 iteraciones cada 15 s: subida de 30 s y meseta de 240 s); decisiones (`ramping-arrival-rate`, 500 por hora); login (3 ráfagas de 20 inicios simultáneos durante la meseta); auditoría (informes a 20 por hora y verificación a 12 por hora); sonda de salud (1 cada 10 s).

**Estrés** (una corrida por grupo; cada nivel con subida corta y meseta de 60 s):

| Grupo | Ejecutor | Niveles (meseta) | Subida |
| :--- | :--- | :--- | :---: |
| Lecturas del panel | `ramping-arrival-rate` | 50, 100 y 150 analistas equivalentes (x2,5, x5 y x7,5 de la tasa nominal) | 15 s |
| Registro de decisiones | `ramping-arrival-rate` | 50, 100 y 150 analistas equivalentes (x2,5, x5 y x7,5) | 15 s |
| Inicio de sesión | `ramping-vus` (sin pausa) | 20, 50 y 100 inicios de sesión simultáneos | 10 s |
| Auditoría | `ramping-vus` (sin pausa) | 1, 3, 5 y 10 pedidos concurrentes | 10 s |

La sonda de salud corre en paralelo en todas las corridas.

---

## 3. Matriz de Cumplimiento de SLAs y Thresholds

### 3.1. Carga (meseta de 240 s)

| Grupo | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Umbral p95 | Estado |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Lecturas del panel | `GET /api/v1/incidents` | 321 | 62.4 ms | 84.5 ms | **100.3 ms** | 654.0 ms | 0.00% | `p95 <2000, p95 <500` | **PASS** |
| Lecturas del panel | `GET /api/v1/decisions` | 321 | 27.6 ms | 36.5 ms | **42.3 ms** | 82.0 ms | 0.00% | `p95 <500` | **PASS** |
| Lecturas del panel | `GET /api/v1/memoria` | 321 | 6.0 ms | 7.9 ms | **8.8 ms** | 62.1 ms | 0.00% | `p95 <500` | **PASS** |
| Registro de decisiones | `POST /api/v1/decision` | 33 | 59.7 ms | 132.6 ms | **167.4 ms** | 274.9 ms | 0.00% | `p95 <500` | **PASS** |
| Inicio de sesión | `POST /api/v1/login` | 60 | 1.00 s | 1.21 s | **1.25 s** | 1.31 s | 0.00% | `p95 <2000` | **PASS** |
| Auditoría (informes y verificación) | `GET /api/v1/reportes (CSV)` | 2 (n < 30) | 75.3 ms | 104.4 ms | **108.0 ms** | 111.6 ms | 0.00% | `p95 <2000` | **PASS** |
| Auditoría (informes y verificación) | `GET /api/v1/audit/verify` | 1 (n < 30) | 46.9 ms | 46.9 ms | **46.9 ms** | 46.9 ms | 0.00% | `p95 <2000` | **PASS** |
| Sonda de salud | `GET /api/v1/healthz` | 28 | 33.4 ms | 241.7 ms | **457.4 ms** | 544.8 ms | - | `max < 2000` | **PASS** |

Sonda de salud durante esta corrida (RNF-COMP-01): 28 sondeos, máximo 544.8 ms, 0 fallido(s) -> **PASS**.

Umbrales: `incidents` p95 < 2 s (RNF-RD-01) y < 500 ms (RNF-RD-09); `decisions` y `memoria` p95 < 500 ms (RNF-RD-09); `decision` p95 < 500 ms (RNF-RD-04); login, informes y verificación p95 < 2 s (umbral interno, la ERS no fija tiempos); error < 1 % en cada meseta; sonda máximo < 2 s (RNF-COMP-01). El estado sale de la evaluación de los umbrales que hace k6 sobre cada subserie, no de una comparación aparte.

### 3.2. Estrés: lecturas del panel

| Meseta (analistas equivalentes) | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Estado |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 50 | `GET /api/v1/incidents` | 200 | 56.0 ms | 68.7 ms | **80.3 ms** | 94.0 ms | 0.00% | **PASS** |
| 50 | `GET /api/v1/decisions` | 200 | 24.3 ms | 32.1 ms | **36.3 ms** | 49.8 ms | 0.00% | **PASS** |
| 50 | `GET /api/v1/memoria` | 200 | 5.6 ms | 7.3 ms | **7.9 ms** | 11.2 ms | 0.00% | **PASS** |
| 100 | `GET /api/v1/incidents` | 400 | 55.3 ms | 71.2 ms | **76.2 ms** | 124.6 ms | 0.00% | **PASS** |
| 100 | `GET /api/v1/decisions` | 400 | 24.3 ms | 32.8 ms | **38.3 ms** | 61.2 ms | 0.00% | **PASS** |
| 100 | `GET /api/v1/memoria` | 400 | 5.4 ms | 7.2 ms | **7.9 ms** | 26.4 ms | 0.00% | **PASS** |
| 150 | `GET /api/v1/incidents` | 600 | 53.3 ms | 73.4 ms | **83.8 ms** | 151.8 ms | 0.00% | **PASS** |
| 150 | `GET /api/v1/decisions` | 600 | 23.6 ms | 32.3 ms | **40.4 ms** | 78.2 ms | 0.00% | **PASS** |
| 150 | `GET /api/v1/memoria` | 600 | 5.3 ms | 21.4 ms | **24.0 ms** | 37.6 ms | 0.00% | **PASS** |

Sonda de salud durante esta corrida (RNF-COMP-01): 23 sondeos, máximo 76.0 ms, 0 fallido(s) -> **PASS**.

**Punto de quiebre**: no se superó ningún umbral en los niveles probados.

### 3.3. Estrés: registro de decisiones

| Meseta (analistas equivalentes) | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Estado |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 50 | `POST /api/v1/decision` | 21 (n < 30) | 51.2 ms | 56.0 ms | **61.4 ms** | 62.5 ms | 0.00% | **PASS** |
| 100 | `POST /api/v1/decision` | 41 | 53.3 ms | 68.7 ms | **72.0 ms** | 78.6 ms | 0.00% | **PASS** |
| 150 | `POST /api/v1/decision` | 63 | 56.2 ms | 78.1 ms | **88.6 ms** | 100.2 ms | 0.00% | **PASS** |

Sonda de salud durante esta corrida (RNF-COMP-01): 23 sondeos, máximo 51.6 ms, 0 fallido(s) -> **PASS**.

**Punto de quiebre**: no se superó ningún umbral en los niveles probados.

### 3.4. Estrés: inicio de sesión

| Meseta (inicios de sesión simultáneos) | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Estado |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 20 | `POST /api/v1/login` | 1263 | 936.4 ms | 1.09 s | **1.19 s** | 1.78 s | 0.00% | **PASS** |
| 50 | `POST /api/v1/login` | 1220 | 2.45 s | 2.81 s | **2.90 s** | 3.18 s | 0.00% | **FAIL** |
| 100 | `POST /api/v1/login` | 1247 | 4.83 s | 5.16 s | **6.26 s** | 8.33 s | 0.00% | **FAIL** |

Sonda de salud durante esta corrida (RNF-COMP-01): 22 sondeos, máximo 617.2 ms, 0 fallido(s) -> **PASS**.

**Punto de quiebre**: meseta de 50 inicios de sesión simultáneos. Incumple: `POST /api/v1/login` p95 <2000 (obtuvo 2.90 s).

### 3.5. Estrés: auditoría (informes y verificación)

| Meseta (pedidos concurrentes) | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Estado |
| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| 1 | `GET /api/v1/reportes (CSV)` | 888 | 45.2 ms | 50.2 ms | **52.6 ms** | 81.8 ms | 0.00% | **PASS** |
| 1 | `GET /api/v1/audit/verify` | 888 | 19.7 ms | 21.4 ms | **22.0 ms** | 38.6 ms | 0.00% | **PASS** |
| 3 | `GET /api/v1/reportes (CSV)` | 873 | 139.2 ms | 168.7 ms | **178.1 ms** | 204.8 ms | 0.00% | **PASS** |
| 3 | `GET /api/v1/audit/verify` | 873 | 59.8 ms | 86.9 ms | **97.7 ms** | 130.5 ms | 0.00% | **PASS** |
| 5 | `GET /api/v1/reportes (CSV)` | 830 | 252.1 ms | 302.2 ms | **320.2 ms** | 404.6 ms | 0.00% | **PASS** |
| 5 | `GET /api/v1/audit/verify` | 830 | 104.2 ms | 147.9 ms | **157.5 ms** | 207.5 ms | 0.00% | **PASS** |
| 10 | `GET /api/v1/reportes (CSV)` | 822 | 517.3 ms | 619.0 ms | **650.4 ms** | 845.7 ms | 0.00% | **PASS** |
| 10 | `GET /api/v1/audit/verify` | 822 | 201.6 ms | 289.5 ms | **315.2 ms** | 474.6 ms | 0.00% | **PASS** |

Sonda de salud durante esta corrida (RNF-COMP-01): 29 sondeos, máximo 1.01 s, 0 fallido(s) -> **PASS**.

**Punto de quiebre**: no se superó ningún umbral en los niveles probados.

---

## 4. Desglose Estadístico de Rendimiento por Endpoint

### 4.1. Latencias de la carga

| Endpoint | Mínimo | Mediana (p50) | Promedio | p90 | p95 | Máximo | Muestras |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `GET /api/v1/incidents` | 47.1 ms | 62.4 ms | 71.1 ms | 84.5 ms | **100.3 ms** | 654.0 ms | 321 |
| `GET /api/v1/decisions` | 19.2 ms | 27.6 ms | 29.1 ms | 36.5 ms | **42.3 ms** | 82.0 ms | 321 |
| `GET /api/v1/memoria` | 4.5 ms | 6.0 ms | 6.4 ms | 7.9 ms | **8.8 ms** | 62.1 ms | 321 |
| `POST /api/v1/decision` | 51.4 ms | 59.7 ms | 81.6 ms | 132.6 ms | **167.4 ms** | 274.9 ms | 33 |
| `POST /api/v1/login` | 327.0 ms | 1.00 s | 966.3 ms | 1.21 s | **1.25 s** | 1.31 s | 60 |
| `GET /api/v1/reportes (CSV)` | 39.1 ms | 75.3 ms | 75.3 ms | 104.4 ms | **108.0 ms** | 111.6 ms | 2 |
| `GET /api/v1/audit/verify` | 46.9 ms | 46.9 ms | 46.9 ms | 46.9 ms | **46.9 ms** | 46.9 ms | 1 |
| `GET /api/v1/healthz` | 23.6 ms | 33.4 ms | 89.2 ms | 241.7 ms | **457.4 ms** | 544.8 ms | 28 |

Iteraciones descartadas por falta de capacidad del generador: **0**.

### 4.2. Latencias del estrés por meseta

Las tablas por meseta están en la sección 3 (columnas p50, p90, p95 y máximo, con las muestras de cada una).

| Grupo | Iteraciones descartadas | Peticiones | Peticiones por segundo | Checks |
| :--- | :---: | :---: | :---: | :---: |
| Lecturas del panel | 0 | 4,385 | 19.49 | 100.00% (8,687 de 8,687) |
| Registro de decisiones | 0 | 212 | 0.94 | 100.00% (341 de 341) |
| Inicio de sesión | 0 | 4,356 | 20.70 | 100.00% (4,356 de 4,356) |
| Auditoría (informes y verificación) | 0 | 7,721 | 27.54 | 100.00% (15,403 de 15,403) |

### 4.3. Validación de contratos y checks funcionales (carga)

```text
✓ Login status 200                         (38 aprobados / 0 fallidos)
✓ Sonda status 200                         (28 aprobados / 0 fallidos)
✓ reportes status 200                      (2 aprobados / 0 fallidos)
✓ reportes con contenido                   (2 aprobados / 0 fallidos)
✓ incidents status 200                     (340 aprobados / 0 fallidos)
✓ incidents estructura                     (340 aprobados / 0 fallidos)
✓ decisions status 200                     (340 aprobados / 0 fallidos)
✓ decisions estructura                     (340 aprobados / 0 fallidos)
✓ memoria status 200                       (340 aprobados / 0 fallidos)
✓ memoria estructura                       (340 aprobados / 0 fallidos)
✓ Decisión status 201                      (37 aprobados / 0 fallidos)
✓ Decisión confirma el registro            (37 aprobados / 0 fallidos)
✓ Login status 200                         (60 aprobados / 0 fallidos)
✓ verify status 200                        (1 aprobados / 0 fallidos)
✓ verify con contenido                     (1 aprobados / 0 fallidos)
----------------------------------------------------------------------
Total de Checks: 2,246 exitosos | 0 fallidos (100.00% éxito)
```

---

## 5. Análisis de Resultados y Cuellos de Botella

Esta sección se genera solo con los resultados de las corridas; no incluye conjeturas sobre la causa de lo observado.

### 5.1. Resultado frente a los requisitos

- **RNF-RD-01** (listado de incidentes p95 < 2 s, 20 analistas, 100 incidentes): **PASS**. p95 en la meseta de carga: 100.3 ms (321 muestras).
- **RNF-RD-04** (registro de decisión p95 < 500 ms, 20 analistas): **PASS**. p95: 167.4 ms con 33 muestras.
- **RNF-RD-09** (hasta 100 analistas, lecturas p95 < 500 ms, error < 1 %): **PASS**. p95 de `incidents`/`decisions`/`memoria` por meseta: 50 analistas: 80.3 ms/36.3 ms/7.9 ms, 100 analistas: 76.2 ms/38.3 ms/7.9 ms, 150 analistas: 83.8 ms/40.4 ms/24.0 ms.
- **RNF-RD-09, recuperación en menos de 1 minuto tras un pico**: no se mide en este entregable (no hay escenario de pico).
- **Muestras:** cada meseta informa su cantidad de muestras. Con menos de 30 (por ejemplo, informes y verificación en la carga, a la tasa real) el p95 es orientativo y se marca `(n < 30)`.

### 5.2. Punto de quiebre por grupo

| Grupo | Primer nivel que incumple | Qué incumple |
| :--- | :--- | :--- |
| Lecturas del panel | ninguno hasta 150 analistas equivalentes | Todos los umbrales se cumplen |
| Registro de decisiones | ninguno hasta 150 analistas equivalentes | Todos los umbrales se cumplen |
| Inicio de sesión | 50 inicios de sesión simultáneos | `POST /api/v1/login` p95 <2000 (obtuvo 2.90 s) |
| Auditoría (informes y verificación) | ninguno hasta 10 pedidos concurrentes | Todos los umbrales se cumplen |

### 5.3. Comportamiento por grupo

- **Lecturas del panel**: el mayor p95 fue 83.8 ms en `GET /api/v1/incidents` durante la meseta de 150; la tasa de error máxima por meseta fue 0.00%; iteraciones descartadas: 0.
- **Registro de decisiones**: el mayor p95 fue 88.6 ms en `POST /api/v1/decision` durante la meseta de 150; la tasa de error máxima por meseta fue 0.00%; iteraciones descartadas: 0.
- **Inicio de sesión**: el mayor p95 fue 6.26 s en `POST /api/v1/login` durante la meseta de 100; la tasa de error máxima por meseta fue 0.00%; iteraciones descartadas: 0.
- **Auditoría (informes y verificación)**: el mayor p95 fue 650.4 ms en `GET /api/v1/reportes (CSV)` durante la meseta de 10; la tasa de error máxima por meseta fue 0.00%; iteraciones descartadas: 0.

### 5.4. Recursos del equipo durante las corridas

| Corrida | Muestras (cada 5 s) | CPU libre mínima | CPU en uso máxima (us+sy) | E/S en espera máxima | Memoria libre mínima (sin caché) |
| :--- | :---: | :---: | :---: | :---: | :---: |
| carga | 56 | 50% | 28% | 28% | 480 MB |
| estres_lecturas | 46 | 71% | 18% | 12% | 212 MB |
| estres_decisiones | 46 | 83% | 11% | 11% | 223 MB |
| estres_login | 43 | 2% | 98% | 10% | 262 MB |
| estres_auditoria | 58 | 75% | 16% | 14% | 978 MB |

La malla ejecuta los 8 servicios dentro de un único proceso de Python y el generador de carga corre en el mismo equipo. Los porcentajes son del equipo completo: no se midió el consumo del proceso de la malla por separado, así que este informe **no atribuye** el deterioro a una causa concreta.

### 5.5. Alcance y límites de este resultado

- **Subcaracterísticas cubiertas:** Comportamiento temporal (RNF-RD-01 y RNF-RD-04) y Capacidad (RNF-RD-09, sin el escenario de pico). No se cubre Utilización de recursos (RNF-RD-02, RNF-RD-05, RNF-RD-08), RNF-RD-03, RNF-RD-06 (verificado en el plan de interfaz) ni RNF-RD-07.
- **Entorno:** malla aislada con los 8 servicios en un solo proceso; las latencias no son comparables con las del stack en contenedores. En el login, el costo de Argon2id se serializa en ese proceso único.
- **Volumen de datos:** 1.400 decisiones (7 días de uso). El registro crece 200 por día y varios endpoints lo leen completo; un año de uso (73.000 decisiones) no se probó.
- **Carga a la tasa real:** informes y verificación ocurren pocas veces por corrida (20 y 12 por hora); su p95 se informa con las muestras que hay.
- **Estrés de decisiones y de lecturas:** los niveles son múltiplos de la tasa nominal (x2,5, x5 y x7,5), no una medida de capacidad máxima.
- **Una sola corrida por escenario:** no hay repeticiones, así que no se estima la variabilidad entre corridas.

