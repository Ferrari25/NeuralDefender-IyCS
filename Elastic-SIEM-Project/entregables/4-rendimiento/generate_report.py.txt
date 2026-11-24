#!/usr/bin/env python3
"""
Generador automático del Informe de Rendimiento (INFORME_RESULTADOS_RENDIMIENTO.md) de NeuralDefender.

Lee, en esta carpeta, lo que dejan las corridas de k6 (entregables/4-rendimiento/correr_k6.sh):
  - summary.json                       escenario de carga (todos los grupos en paralelo)
  - summary_estres_<grupo>.json        estrés de cada grupo: lecturas, decisiones, login y auditoria
  - corrida_<corrida>.json             fecha, hora y duración real de cada corrida
  - vmstat_<corrida>.txt               CPU y memoria del equipo durante la corrida (opcional)

Todo lo que dice el informe sale de esos archivos: ningún valor ni conclusión está escrito a mano. El p95 de
cada meseta sale de las subseries `http_req_duration{grupo,endpoint,fase}` que declara k6_api_test.js.

Uso:
    python tests/performance/generate_report.py
"""

import json
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
REPORT_FILE = BASE_DIR / "INFORME_RESULTADOS_RENDIMIENTO.md"
GRUPOS = ["lecturas", "decisiones", "login", "auditoria"]
MUESTRA_MINIMA = 30   # con menos muestras por meseta, el p95 es solo informativo

NOMBRE_GRUPO = {"lecturas": "Lecturas del panel", "decisiones": "Registro de decisiones", "login": "Inicio de sesión",
                "auditoria": "Auditoría (informes y verificación)", "sonda": "Sonda de salud"}
ENDPOINTS = {  # grupo -> [(etiqueta de k6, ruta)]
    "lecturas": [("incidents", "GET /api/v1/incidents"), ("decisions", "GET /api/v1/decisions"), ("memoria", "GET /api/v1/memoria")],
    "decisiones": [("decision", "POST /api/v1/decision")],
    "login": [("login", "POST /api/v1/login")],
    "auditoria": [("reportes", "GET /api/v1/reportes (CSV)"), ("verify", "GET /api/v1/audit/verify")],
    "sonda": [("healthz", "GET /api/v1/healthz")],
}
UNIDAD_NIVEL = {"lecturas": "analistas equivalentes", "decisiones": "analistas equivalentes",
                "login": "inicios de sesión simultáneos", "auditoria": "pedidos concurrentes"}
# Perfil de uso (los mismos valores y supuestos que declara k6_api_test.js).
PERFIL = [
    ("incidents, decisions y memoria (cada uno)", "Los 3 roles", "1 cada 15 s con el panel abierto", "1,33 + 0,14 (recargas tras decidir)",
     "app.js:1308 (refresco de 15 s, RF-SUP-07); 20 analistas / 15 s"),
    ("POST /api/v1/decision", "Analista", "200 por día en un turno de 8 h", "0,14",
     "ERS línea 621 (200 decisiones diarias); 20 x 200 / 8 h = 500 por hora"),
    ("POST /api/v1/login", "Todos", "1 por sesión (máx. 8 h); ráfaga de inicio de turno", "0,0007 de promedio; ráfaga de 20 simultáneos",
     "sesion_web.py: sesión máxima de 8 h; supuesto de ráfaga"),
    ("GET /api/v1/reportes", "Auditor y analista", "1 por analista por hora (supuesto)", "0,0056", "Supuesto declarado en el plan: ERS sin frecuencia"),
    ("GET /api/v1/audit/verify", "Auditor", "1 cada 10 min con 2 auditores (supuesto)", "0,0033", "Supuesto declarado en el plan; solo vía API. En la carga se fuerza 1 verificación en la meseta"),
    ("GET /api/v1/healthz", "Contenedor (sonda)", "1 cada 10 s", "0,1", "docker-compose.yml:461 (intervalo del healthcheck)"),
]


def fmt(ms):
    if ms is None:
        return "N/A"
    return f"{ms / 1000:.2f} s" if ms >= 1000 else f"{ms:.1f} ms"


def vals(metrics, clave):
    obj = metrics.get(clave, {})
    return obj.get("values", obj) if isinstance(obj, dict) else {}


def umbrales(metrics, clave):
    return {e: (r.get("ok") if isinstance(r, dict) else bool(r)) for e, r in (metrics.get(clave, {}).get("thresholds") or {}).items()}


def tasa_error(metrics, grupo, fase):
    v = vals(metrics, f"http_req_failed{{grupo:{grupo},fase:{fase}}}")
    fallidas, ok = v.get("passes", 0), v.get("fails", 0)
    total = fallidas + ok
    return (fallidas / total * 100) if total else None


def serie(metrics, grupo, endpoint, fase):
    clave = f"http_req_duration{{grupo:{grupo},endpoint:{endpoint},fase:{fase}}}"
    return vals(metrics, clave), umbrales(metrics, clave)


def mesetas_de(metrics, grupo):
    """Mesetas (en orden numérico) que tienen subserie declarada para el grupo."""
    fases = set()
    for clave in metrics:
        if clave.startswith("http_req_failed{") and f"grupo:{grupo}," in clave and "fase:meseta_" in clave:
            fases.add(clave.split("fase:")[1].rstrip("}"))
    def orden(f):
        sufijo = f.split("_", 1)[1]
        return (0, int(sufijo)) if sufijo.isdigit() else (1, 0)
    return sorted(fases, key=orden)


def evaluar(metrics, grupo, fase):
    """Resultado de una meseta: p95 por endpoint, tasa de error y si todos sus umbrales se cumplen."""
    filas, todos_ok, n_min = [], True, None
    for etiqueta, ruta in ENDPOINTS[grupo]:
        v, thr = serie(metrics, grupo, etiqueta, fase)
        ok = all(thr.values()) if thr else None
        todos_ok = todos_ok and (ok is not False)
        n = int(v.get("count", 0))
        n_min = n if n_min is None else min(n_min, n)
        filas.append({"endpoint": ruta, "v": v, "thr": thr, "ok": ok, "n": n})
    error = tasa_error(metrics, grupo, fase)
    thr_error = umbrales(metrics, f"http_req_failed{{grupo:{grupo},fase:{fase}}}")
    ok_error = all(thr_error.values()) if thr_error else None
    return {"fase": fase, "filas": filas, "error": error, "ok_error": ok_error,
            "ok": todos_ok and (ok_error is not False), "n_min": n_min or 0}


def leer_corrida(base):
    ruta = BASE_DIR / f"corrida_{base}.json"
    return json.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else None


def vmstat_de(base):
    ruta = BASE_DIR / f"vmstat_{base}.txt"
    if not ruta.exists():
        return None
    columnas, filas = None, []
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        partes = linea.split()
        if partes[:2] == ["r", "b"]:
            columnas = partes
        elif columnas and len(partes) >= len(columnas) - 1 and partes[0].isdigit():
            filas.append(dict(zip(columnas, partes, strict=False)))
    filas = filas[1:] or filas   # la primera fila de vmstat es el promedio desde el arranque
    if not filas:
        return None
    num = lambda k: [float(f[k]) for f in filas if k in f]  # noqa: E731
    return {"muestras": len(filas), "idle_min": min(num("id")), "us_sy_max": max(a + b for a, b in zip(num("us"), num("sy"), strict=False)),
            "wa_max": max(num("wa")), "libre_min_mb": min(num("free")) / 1024}


def cargar():
    datos = {}
    carga = BASE_DIR / "summary.json"
    if carga.exists():
        datos["carga"] = json.loads(carga.read_text(encoding="utf-8"))
    for g in GRUPOS:
        ruta = BASE_DIR / f"summary_estres_{g}.json"
        if ruta.exists():
            datos[g] = json.loads(ruta.read_text(encoding="utf-8"))
    return datos


def estado(ok):
    return "N/A" if ok is None else ("PASS" if ok else "FAIL")


def sonda_de(metrics):
    """Resumen de la sonda de salud de una corrida (RNF-COMP-01: cada sondeo con 200 y en menos de 2 s)."""
    d = vals(metrics, "http_req_duration{grupo:sonda}")
    f = vals(metrics, "http_req_failed{grupo:sonda}")
    ok = all(list(umbrales(metrics, "http_req_duration{grupo:sonda}").values()) + list(umbrales(metrics, "http_req_failed{grupo:sonda}").values()))
    return {"n": int(d.get("count", 0)), "max": d.get("max"), "fallidos": int(f.get("passes", 0)), "ok": ok}


def linea_sonda(metrics):
    s = sonda_de(metrics)
    return (f"Sonda de salud durante esta corrida (RNF-COMP-01): {s['n']} sondeos, máximo {fmt(s['max'])}, {s['fallidos']} fallido(s) -> **{estado(s['ok'])}**.\n")


def incumplidos(data):
    """Umbrales que k6 marcó como incumplidos, en texto corto."""
    out = []
    for clave, m in data.get("metrics", {}).items():
        for expr, res in (m.get("thresholds") or {}).items():
            if not (res.get("ok") if isinstance(res, dict) else res):
                out.append(f"{clave.split('{')[0]}{{{clave.split('{', 1)[1]} {expr}" if "{" in clave else f"{clave} {expr}")
    return out


def tabla_carga(metrics):
    filas = ["| Grupo | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Umbral p95 | Estado |", "| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"]
    for g in GRUPOS:
        fases = mesetas_de(metrics, g)
        if not fases:
            continue
        r = evaluar(metrics, g, fases[0])
        for f in r["filas"]:
            limites = ", ".join(e.replace("p(95)", "p95 ") for e in f["thr"]) or "-"
            if f["n"] == 0:
                filas.append(f"| {NOMBRE_GRUPO[g]} | `{f['endpoint']}` | 0 | - | - | - | - | - | `{limites}` | **SIN MUESTRAS** |")
                continue
            err = "N/A" if r["error"] is None else f"{r['error']:.2f}%"
            nota = " (n < 30)" if f["n"] < MUESTRA_MINIMA else ""
            filas.append(f"| {NOMBRE_GRUPO[g]} | `{f['endpoint']}` | {f['n']}{nota} | {fmt(f['v'].get('med'))} | {fmt(f['v'].get('p(90)'))} | "
                         f"**{fmt(f['v'].get('p(95)'))}** | {fmt(f['v'].get('max'))} | {err} | `{limites}` | **{estado(f['ok'])}** |")
    sonda = vals(metrics, "http_req_duration{grupo:sonda}")
    thr = umbrales(metrics, "http_req_duration{grupo:sonda}")
    filas.append(f"| {NOMBRE_GRUPO['sonda']} | `GET /api/v1/healthz` | {int(sonda.get('count', 0))} | {fmt(sonda.get('med'))} | {fmt(sonda.get('p(90)'))} | "
                 f"**{fmt(sonda.get('p(95)'))}** | {fmt(sonda.get('max'))} | - | `max < 2000` | **{estado(all(thr.values()) if thr else None)}** |")
    return "\n".join(filas)


def tabla_estres(grupo, metrics):
    filas = [f"| Meseta ({UNIDAD_NIVEL[grupo]}) | Endpoint | Muestras | p50 | p90 | p95 | Máximo | Error | Estado |", "| :---: | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |"]
    resultados = []
    for fase in mesetas_de(metrics, grupo):
        r = evaluar(metrics, grupo, fase)
        resultados.append(r)
        nivel = fase.split("_", 1)[1]
        for f in r["filas"]:
            err = "N/A" if r["error"] is None else f"{r['error']:.2f}%"
            nota = " (n < 30)" if f["n"] < MUESTRA_MINIMA else ""
            filas.append(f"| {nivel} | `{f['endpoint']}` | {f['n']}{nota} | {fmt(f['v'].get('med'))} | {fmt(f['v'].get('p(90)'))} | "
                         f"**{fmt(f['v'].get('p(95)'))}** | {fmt(f['v'].get('max'))} | {err} | **{estado(f['ok'] and r['ok_error'] is not False if f['ok'] is not None else None)}** |")
    return "\n".join(filas), resultados


def quiebre(resultados):
    """Primera meseta que incumple algún umbral, o None."""
    for r in resultados:
        if not r["ok"]:
            return r
    return None


def umbrales_incumplidos(r, grupo):
    out = []
    for f in r["filas"]:
        for expr, ok in f["thr"].items():
            if not ok:
                out.append(f"`{f['endpoint']}` {expr.replace('p(95)', 'p95 ')} (obtuvo {fmt(f['v'].get('p(95)'))})")
    if r["ok_error"] is False:
        out.append(f"tasa de error {r['error']:.2f}% (límite 1 %)")
    return out


def checks_de(data):
    total = aprobados = 0
    detalle = []

    def recorrer(grupo):
        nonlocal total, aprobados
        crudo = grupo.get("checks", [])
        for chk in (crudo.values() if isinstance(crudo, dict) else crudo):
            p, f = chk.get("passes", 0), chk.get("fails", 0)
            total += p + f
            aprobados += p
            detalle.append(f"{'✓' if f == 0 else '✗'} {chk.get('name', 'Unnamed'):<40} ({p} aprobados / {f} fallidos)")
        crudo = grupo.get("groups", [])
        for sub in (crudo.values() if isinstance(crudo, dict) else crudo):
            recorrer(sub)

    recorrer(data.get("root_group", {}))
    return total, aprobados, detalle


def main():
    datos = cargar()
    if not datos:
        print("Error: no hay ningún summary de k6. Corré primero: ./entregables/4-rendimiento/correr_k6.sh")
        return
    corridas = {b: leer_corrida(b) for b in ["carga"] + [f"estres_{g}" for g in GRUPOS]}
    inicios = [c["inicio"] for c in corridas.values() if c]
    fines = [c["fin"] for c in corridas.values() if c]
    segundos_total = sum(c["segundos"] for c in corridas.values() if c)
    rango = f"{min(inicios)[:19].replace('T', ' ')} a {max(fines)[:19].replace('T', ' ')}" if inicios else "sin registro"
    ahora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    p = []
    p.append(f"""# Informe de Pruebas de Rendimiento de APIs (SDET Performance Test Report)

**Proyecto**: NeuralDefender - Elastic-SIEM-Project
**Fecha de generación del informe**: {ahora}
**Fecha y hora de la corrida**: {rango}
**Herramienta**: Grafana k6 (`grafana/k6:1.3.0`)
**Ambiente**: malla aislada de los 8 servicios (`http://127.0.0.1:18080`): 100 incidentes, 20 analistas y 1.400 decisiones sembradas (7 días de uso a 200 por día), sin ciclo del pipeline
**Autor**: Equipo NeuralDefender-IyCS

---

## 1. Resumen Ejecutivo (Executive Summary)

Cada grupo de endpoints se prueba con **su propio perfil de uso**, no con una carga única. La **carga** corre los 5 grupos en paralelo, cada uno con su tasa real; el **estrés** corre una vez por grupo, con niveles propios y, en cada nivel, una subida corta y una meseta sostenida de 60 s. El p95 de cada meseta se mide por separado.
""")
    p.append("| Corrida | Inicio | Duración real | Código de k6 | Umbrales incumplidos | Nota |\n| :--- | :--- | :---: | :---: | :--- | :--- |")
    for base, c in corridas.items():
        if c:
            nombre = "Carga (todos los grupos)" if base == "carga" else f"Estrés: {NOMBRE_GRUPO[c['grupo']]}"
            origen = datos.get("carga" if base == "carga" else c["grupo"])
            fallos = "; ".join(f"`{x}`" for x in incumplidos(origen)) if origen else "-"
            p.append(f"| {nombre} | {c['inicio'][:19].replace('T', ' ')} | {c['segundos'] // 60}:{c['segundos'] % 60:02d} | {c['codigo_k6']} | {fallos or 'ninguno'} | {c.get('nota') or '-'} |")
    p.append(f"\nDuración total medida: **{segundos_total // 60}:{segundos_total % 60:02d}** (suma de las corridas de k6, sin contar el reinicio de la malla entre ellas). "
             "Código de k6: 0 significa que se cumplieron todos los umbrales; 99, que alguno no.\n")

    if "carga" in datos:
        m = datos["carga"]["metrics"]
        thr_carga = [ok for k in m if k.startswith("http_req_") and "grupo:" in k for ok in umbrales(m, k).values()]
        reqs = vals(m, "http_reqs")
        total_c, aprob_c, _ = checks_de(datos["carga"])
        p.append(f"- **Carga**: {int(reqs.get('count', 0)):,} peticiones, {reqs.get('rate', 0):.2f} por segundo, checks {aprob_c / total_c * 100 if total_c else 0:.2f}% "
                 f"({aprob_c:,} de {total_c:,}). Umbrales por meseta: **{'todos cumplidos' if all(thr_carga) else 'alguno NO cumplido'}** ({sum(thr_carga)} de {len(thr_carga)}).")
    for g in GRUPOS:
        if g in datos:
            _, res = tabla_estres(g, datos[g]["metrics"])
            q = quiebre(res)
            if q is None:
                p.append(f"- **Estrés de {NOMBRE_GRUPO[g].lower()}**: sin punto de quiebre hasta {res[-1]['fase'].split('_', 1)[1]} {UNIDAD_NIVEL[g]}.")
            else:
                p.append(f"- **Estrés de {NOMBRE_GRUPO[g].lower()}**: primer incumplimiento en la meseta de **{q['fase'].split('_', 1)[1]} {UNIDAD_NIVEL[g]}**.")

    p.append("""
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
| :--- | :--- | :--- | :---: | :--- |""")
    for fila in PERFIL:
        p.append("| " + " | ".join(fila) + " |")
    p.append("""
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
""")
    if "carga" in datos:
        p.append("### 3.1. Carga (meseta de 240 s)\n\n" + tabla_carga(datos["carga"]["metrics"]) + "\n")
        p.append(linea_sonda(datos["carga"]["metrics"]))
        p.append("Umbrales: `incidents` p95 < 2 s (RNF-RD-01) y < 500 ms (RNF-RD-09); `decisions` y `memoria` p95 < 500 ms (RNF-RD-09); `decision` p95 < 500 ms (RNF-RD-04); "
                 "login, informes y verificación p95 < 2 s (umbral interno, la ERS no fija tiempos); error < 1 % en cada meseta; sonda máximo < 2 s (RNF-COMP-01). "
                 "El estado sale de la evaluación de los umbrales que hace k6 sobre cada subserie, no de una comparación aparte.\n")
    n = 2
    resultados_estres = {}
    for g in GRUPOS:
        if g in datos:
            tabla, res = tabla_estres(g, datos[g]["metrics"])
            resultados_estres[g] = res
            p.append(f"### 3.{n}. Estrés: {NOMBRE_GRUPO[g].lower()}\n\n{tabla}\n")
            p.append(linea_sonda(datos[g]["metrics"]))
            q = quiebre(res)
            if q:
                p.append(f"**Punto de quiebre**: meseta de {q['fase'].split('_', 1)[1]} {UNIDAD_NIVEL[g]}. Incumple: " + "; ".join(umbrales_incumplidos(q, g)) + ".\n")
            else:
                p.append("**Punto de quiebre**: no se superó ningún umbral en los niveles probados.\n")
            n += 1

    p.append("---\n\n## 4. Desglose Estadístico de Rendimiento por Endpoint\n")
    if "carga" in datos:
        mc = datos["carga"]["metrics"]
        p.append("### 4.1. Latencias de la carga\n\n| Endpoint | Mínimo | Mediana (p50) | Promedio | p90 | p95 | Máximo | Muestras |\n| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
        for g in GRUPOS + ["sonda"]:
            fases = mesetas_de(mc, g)
            for etiqueta, ruta in ENDPOINTS[g]:
                clave = (f"http_req_duration{{grupo:{g},endpoint:{etiqueta},fase:{fases[0]}}}" if g != "sonda" and fases else "http_req_duration{grupo:sonda}")
                v = vals(mc, clave)
                p.append(f"| `{ruta}` | {fmt(v.get('min'))} | {fmt(v.get('med'))} | {fmt(v.get('avg'))} | {fmt(v.get('p(90)'))} | **{fmt(v.get('p(95)'))}** | {fmt(v.get('max'))} | {int(v.get('count', 0))} |")
        descartadas = vals(mc, "dropped_iterations").get("count", 0)
        p.append(f"\nIteraciones descartadas por falta de capacidad del generador: **{int(descartadas)}**.\n")
    p.append("### 4.2. Latencias del estrés por meseta\n\nLas tablas por meseta están en la sección 3 (columnas p50, p90, p95 y máximo, con las muestras de cada una).\n")
    p.append("| Grupo | Iteraciones descartadas | Peticiones | Peticiones por segundo | Checks |\n| :--- | :---: | :---: | :---: | :---: |")
    for g in GRUPOS:
        if g in datos:
            md = datos[g]["metrics"]
            reqs = vals(md, "http_reqs")
            tot, ap, _ = checks_de(datos[g])
            p.append(f"| {NOMBRE_GRUPO[g]} | {int(vals(md, 'dropped_iterations').get('count', 0))} | {int(reqs.get('count', 0)):,} | {reqs.get('rate', 0):.2f} | {ap / tot * 100 if tot else 0:.2f}% ({ap:,} de {tot:,}) |")
    p.append("\n### 4.3. Validación de contratos y checks funcionales (carga)\n")
    if "carga" in datos:
        tot, ap, detalle = checks_de(datos["carga"])
        p.append("```text\n" + "\n".join(detalle) + f"\n{'-' * 70}\nTotal de Checks: {ap:,} exitosos | {tot - ap:,} fallidos ({ap / tot * 100 if tot else 0:.2f}% éxito)\n```\n")

    # ─── 5. Análisis ───
    p.append("---\n\n## 5. Análisis de Resultados y Cuellos de Botella\n\nEsta sección se genera solo con los resultados de las corridas; no incluye conjeturas sobre la causa de lo observado.\n")
    p.append("### 5.1. Resultado frente a los requisitos\n")
    if "carga" in datos:
        mc = datos["carga"]["metrics"]
        v_inc, t_inc = serie(mc, "lecturas", "incidents", "meseta_20")
        v_dec, t_dec = serie(mc, "decisiones", "decision", "meseta_20")
        p.append(f"- **RNF-RD-01** (listado de incidentes p95 < 2 s, 20 analistas, 100 incidentes): **{estado(all(t_inc.values()) if t_inc else None)}**. p95 en la meseta de carga: {fmt(v_inc.get('p(95)'))} ({int(v_inc.get('count', 0))} muestras).")
        p.append(f"- **RNF-RD-04** (registro de decisión p95 < 500 ms, 20 analistas): **{estado(all(t_dec.values()) if t_dec else None)}**. p95: {fmt(v_dec.get('p(95)'))} con {int(v_dec.get('count', 0))} muestras"
                 f"{' (menos de 30: el p95 es orientativo)' if v_dec.get('count', 0) < MUESTRA_MINIMA else ''}.")
    if "lecturas" in datos:
        res = resultados_estres["lecturas"]
        hasta_100 = [r for r in res if r["fase"] in ("meseta_50", "meseta_100")]
        cumple = bool(hasta_100) and all(r["ok"] for r in hasta_100)
        detalle = ", ".join(f"{r['fase'].split('_', 1)[1]} analistas: " + "/".join(fmt(f["v"].get("p(95)")) for f in r["filas"]) for r in res)
        p.append(f"- **RNF-RD-09** (hasta 100 analistas, lecturas p95 < 500 ms, error < 1 %): **{estado(cumple)}**. p95 de `incidents`/`decisions`/`memoria` por meseta: {detalle}.")
    p.append("- **RNF-RD-09, recuperación en menos de 1 minuto tras un pico**: no se mide en este entregable (no hay escenario de pico).")
    p.append("- **Muestras:** cada meseta informa su cantidad de muestras. Con menos de 30 (por ejemplo, informes y verificación en la carga, a la tasa real) el p95 es orientativo y se marca `(n < 30)`.\n")

    p.append("### 5.2. Punto de quiebre por grupo\n\n| Grupo | Primer nivel que incumple | Qué incumple |\n| :--- | :--- | :--- |")
    for g in GRUPOS:
        if g in resultados_estres:
            q = quiebre(resultados_estres[g])
            if q:
                p.append(f"| {NOMBRE_GRUPO[g]} | {q['fase'].split('_', 1)[1]} {UNIDAD_NIVEL[g]} | " + "; ".join(umbrales_incumplidos(q, g)) + " |")
            else:
                p.append(f"| {NOMBRE_GRUPO[g]} | ninguno hasta {resultados_estres[g][-1]['fase'].split('_', 1)[1]} {UNIDAD_NIVEL[g]} | Todos los umbrales se cumplen |")
    p.append("")

    p.append("### 5.3. Comportamiento por grupo\n")
    for g in GRUPOS:
        if g in resultados_estres:
            res = resultados_estres[g]
            peor = max(((f["v"].get("p(95)") or 0, f["endpoint"], r["fase"]) for r in res for f in r["filas"]), key=lambda t: t[0])
            err_max = max((r["error"] or 0) for r in res)
            p.append(f"- **{NOMBRE_GRUPO[g]}**: el mayor p95 fue {fmt(peor[0])} en `{peor[1]}` durante la meseta de {peor[2].split('_', 1)[1]}; "
                     f"la tasa de error máxima por meseta fue {err_max:.2f}%; iteraciones descartadas: {int(vals(datos[g]['metrics'], 'dropped_iterations').get('count', 0))}.")
    p.append("")

    p.append("### 5.4. Recursos del equipo durante las corridas\n\n| Corrida | Muestras (cada 5 s) | CPU libre mínima | CPU en uso máxima (us+sy) | E/S en espera máxima | Memoria libre mínima (sin caché) |\n| :--- | :---: | :---: | :---: | :---: | :---: |")
    for base, c in corridas.items():
        v = vmstat_de(base) if c else None
        if v:
            p.append(f"| {base} | {v['muestras']} | {v['idle_min']:.0f}% | {v['us_sy_max']:.0f}% | {v['wa_max']:.0f}% | {v['libre_min_mb']:.0f} MB |")
    p.append("\nLa malla ejecuta los 8 servicios dentro de un único proceso de Python y el generador de carga corre en el mismo equipo. Los porcentajes son del equipo completo: "
             "no se midió el consumo del proceso de la malla por separado, así que este informe **no atribuye** el deterioro a una causa concreta.\n")

    p.append("""### 5.5. Alcance y límites de este resultado

- **Subcaracterísticas cubiertas:** Comportamiento temporal (RNF-RD-01 y RNF-RD-04) y Capacidad (RNF-RD-09, sin el escenario de pico). No se cubre Utilización de recursos (RNF-RD-02, RNF-RD-05, RNF-RD-08), RNF-RD-03, RNF-RD-06 (verificado en el plan de interfaz) ni RNF-RD-07.
- **Entorno:** malla aislada con los 8 servicios en un solo proceso; las latencias no son comparables con las del stack en contenedores. En el login, el costo de Argon2id se serializa en ese proceso único.
- **Volumen de datos:** 1.400 decisiones (7 días de uso). El registro crece 200 por día y varios endpoints lo leen completo; un año de uso (73.000 decisiones) no se probó.
- **Carga a la tasa real:** informes y verificación ocurren pocas veces por corrida (20 y 12 por hora); su p95 se informa con las muestras que hay.
- **Estrés de decisiones y de lecturas:** los niveles son múltiplos de la tasa nominal (x2,5, x5 y x7,5), no una medida de capacidad máxima.
- **Una sola corrida por escenario:** no hay repeticiones, así que no se estima la variabilidad entre corridas.
""")
    REPORT_FILE.write_text("\n".join(p) + "\n", encoding="utf-8")
    print(f"Informe generado exitosamente en: {REPORT_FILE}")


if __name__ == "__main__":
    main()
