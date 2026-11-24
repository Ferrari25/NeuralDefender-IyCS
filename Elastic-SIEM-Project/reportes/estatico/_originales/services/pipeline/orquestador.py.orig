#!/usr/bin/env python3
"""
Orquestador del pipeline NeuralDefender: detección → análisis → acción.

Encadena las etapas llamando a cada servicio por HTTP, en orden:
  1. collector   — captura de Elasticsearch               (tolerable)
  2. classifier  — Agente 1, clasificación determinística (crítica)
  3. analyst     — Agente 2, análisis LLM con fallback    (crítica)
  4. audit       — registra la corrida en el historial append-only

Si Elasticsearch no está disponible, la etapa 1 falla de forma controlada y el
ciclo sigue con la última captura que guardó el collector (modo demo offline),
o sin ninguna, clasificando solo desde `network_logs/`. Al terminar, el reporte
queda en `data/siem_incidents.json` (volumen de este servicio), listo para que
el gateway se lo muestre al analista.

**Antes esto era la única excepción de la certificación de no-autonomía**: el
orquestador lanzaba las etapas con `subprocess.run`. Ahora no ejecuta ningún
proceso; sus únicas acciones son las llamadas HTTP de `ETAPAS`, todas con
destino y ruta literales (`tests/test_no_autonomy.py` lo verifica por AST).
"""

from __future__ import annotations

import threading

from siem_lib import load_json, now_iso, write_json
from siem_servicios import ServicioNoDisponible, llamar

INCIDENTS_FILE = "data/siem_incidents.json"

# Tiempos máximos por etapa. El análisis es el más largo: con el LLM encendido
# hace una llamada al LLM (Gemma local o Gemini) por incidente.
TIMEOUT_CAPTURA = 60
TIMEOUT_CLASIFICACION = 60
# Se le manda al analyst como `plazo_s` en cada pedido: corta el LLM a tiempo
# para responder antes de que se venza, cualquiera sea su presupuesto propio.
TIMEOUT_ANALISIS = 600

# Un ciclo a la vez: dos corridas simultáneas escribirían el mismo reporte.
_en_curso = threading.Lock()


class ErrorDeEtapa(RuntimeError):
    """Una etapa crítica falló y el ciclo se abortó."""


class CicloEnCurso(RuntimeError):
    """Ya hay un ciclo corriendo."""


def _titulo(texto: str) -> None:
    print(f"\n{'#' * 64}\n# {texto}\n{'#' * 64}", flush=True)


def _captura_del_siem(etapas: list[dict]) -> dict:
    """Etapa 1 (tolerable): captura nueva, o la última buena, o ninguna."""
    _titulo("Extracción de datos del SIEM (collector)")
    try:
        r = llamar("collector", "POST", "/v1/snapshots", timeout=TIMEOUT_CAPTURA)
        if r.status == 201:
            etapas.append({"etapa": "collector", "estado": "ok"})
            return r.datos["snapshot"]
        motivo = (r.datos or {}).get("error", f"HTTP {r.status}")
        previa = llamar("collector", "GET", "/v1/snapshots/latest")
    except ServicioNoDisponible as e:
        etapas.append({"etapa": "collector", "estado": "omitida", "motivo": str(e)})
        print(f"[INFO] {e}; se clasifica solo desde network_logs/.")
        return {}

    if previa.status == 200:
        etapas.append({"etapa": "collector", "estado": "captura_previa", "motivo": motivo})
        print(f"[INFO] {motivo}\n[INFO] Continúo con la última captura guardada.")
        return previa.datos["snapshot"]
    etapas.append({"etapa": "collector", "estado": "sin_captura", "motivo": motivo})
    print(f"[INFO] {motivo}\n[INFO] Sin captura previa: se clasifica solo desde network_logs/.")
    return {}


def _etapa_critica(nombre: str, respuesta_ok: bool, status: int, datos) -> None:
    if not respuesta_ok:
        motivo = (datos or {}).get("error") if isinstance(datos, dict) else None
        raise ErrorDeEtapa(f"la etapa '{nombre}' falló (HTTP {status}): {motivo or 'sin detalle'}")


def _incidentes_previos() -> list[dict]:
    """Los incidentes del último reporte (vacío si no hay reporte o está roto)."""
    try:
        anterior = load_json(INCIDENTS_FILE)
    except (OSError, ValueError):
        return []
    incidentes = anterior.get("incidents") if isinstance(anterior, dict) else None
    if not isinstance(incidentes, list):
        return []
    return [i for i in incidentes if isinstance(i, dict) and isinstance(i.get("incident_id"), str)]


def _identidad_previa() -> list[dict]:
    """Lo mínimo que el classifier necesita para que un ataque en curso conserve su ID."""
    return [{k: i.get(k) for k in ("incident_id", "first_seen", "last_seen")}
            for i in _incidentes_previos()]


def _analisis_previos() -> dict[str, dict]:
    """Los análisis del último reporte, por `incident_id`.

    Se le pasan al analyst para que reutilice los de incidentes que no
    cambiaron en vez de volver a generarlos con el LLM (ver
    `siem_agent._huella`). Si no hay reporte o está roto, no hay previos.
    """
    return {i["incident_id"]: i["analysis"] for i in _incidentes_previos()
            if isinstance(i.get("analysis"), dict)}


def ejecutar_ciclo() -> dict:
    """Corre un ciclo completo y devuelve `{report, etapas}`.

    Lanza `CicloEnCurso` si ya hay otro corriendo y `ErrorDeEtapa` si una etapa
    crítica falla; en ese caso el reporte anterior queda intacto.
    """
    if not _en_curso.acquire(blocking=False):
        raise CicloEnCurso("ya hay un ciclo de análisis en curso")
    try:
        etapas: list[dict] = []
        siem_data = _captura_del_siem(etapas)

        _titulo("Agente 1 — Clasificación determinística (classifier)")
        try:
            r = llamar("classifier", "POST", "/v1/classify",
                       {"siem_data": siem_data, "anteriores": _identidad_previa()},
                       timeout=TIMEOUT_CLASIFICACION)
            _etapa_critica("classifier", r.ok, r.status, r.datos)
            report = r.datos
            etapas.append({"etapa": "classifier", "estado": "ok"})

            _titulo("Agente 2 — Análisis LLM (analyst)")
            r = llamar("analyst", "POST", "/v1/analyze",
                       {"incidents": report["incidents"], "previos": _analisis_previos(),
                        "plazo_s": TIMEOUT_ANALISIS},
                       timeout=TIMEOUT_ANALISIS)
            _etapa_critica("analyst", r.ok, r.status, r.datos)
            etapas.append({"etapa": "analyst", "estado": "ok"})
        except ServicioNoDisponible as e:
            raise ErrorDeEtapa(str(e)) from e

        report["incidents"] = r.datos["incidents"]
        report["analyzed_at"] = r.datos.get("analyzed_at") or now_iso()
        report["analyst_mode"] = r.datos.get("analyst_mode", "fallback")
        write_json(INCIDENTS_FILE, report)

        # Registro inmutable de la corrida (no se sobreescribe nunca). Si el
        # servicio de auditoría no lo acepta, el ciclo se informa como fallido:
        # una corrida sin rastro en el historial no debería pasar desapercibida.
        try:
            r = llamar("audit", "POST", "/v1/analysis-history", {
                "analyst_mode": report["analyst_mode"],
                "incident_count": len(report["incidents"]),
                "incident_ids": [i["incident_id"] for i in report["incidents"]],
            })
        except ServicioNoDisponible as e:
            raise ErrorDeEtapa(f"el reporte se guardó, pero no se pudo registrar la corrida: {e}") from e
        _etapa_critica("audit", r.ok, r.status, r.datos)
        etapas.append({"etapa": "audit", "estado": "ok"})
        return {"report": report, "etapas": etapas}
    finally:
        _en_curso.release()
