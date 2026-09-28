"""La severidad que el Agente 2 entrega tiene que ser pintable (tarea **G1**).

El panel arma la clase CSS de la insignia como `"b-" + sev.toUpperCase()`. El prompt
le **pide** al LLM `LOW|MEDIUM|HIGH|CRITICAL`, pero pedirlo no es garantizarlo: un
`"alta"` produce `.b-ALTA`, que no existe en `app.css`. La insignia se dibujaba sin
color y la severidad dejaba de verse — en el panel donde un analista decide.

El camino de respaldo ya normalizaba (`_SEV_MAP` con default). El del LLM no: su
salida se pasaba tal cual.

**Lo importante del diseño:** ante un valor irreconocible no se cae a `MEDIUM`. Eso
degradaría en silencio un incidente crítico, que es mucho peor que una insignia rara.
Se usa la severidad determinística del Agente 1, que es la confiable — el mismo
criterio que el resto del proyecto: cuando el LLM no sirve, manda lo determinístico.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import siem_agent

RAIZ = Path(__file__).resolve().parent.parent.parent
CLASES_CSS = set(re.findall(r"\.b-([A-Z]+)\s*\{",
                            (RAIZ / "static" / "app.css").read_text(encoding="utf-8")))


def _incidente(severidad_determinista: str = "alta") -> dict:
    """Lo mínimo que `_fallback_analysis` necesita para armar su plantilla."""
    return {"incident_id": "INC-T-1",
            "classification": {"severity": severidad_determinista,
                               "attack_type": "port_scan",
                               "false_positive_likelihood": "baja",
                               "mitre_technique": "T1046"},
            "source_ip": "198.51.100.5",
            "event_count": 26,
            "recommended_actions": []}


# ─── Valores que el LLM debería devolver ─────────────────────────────────────

@pytest.mark.parametrize("valor", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_los_valores_validos_pasan_intactos(valor: str):
    assert siem_agent._normalizar_severidad(valor, _incidente()) == valor


@pytest.mark.parametrize("valor", ["low", "High", " critical ", "mEdIuM"])
def test_se_tolera_la_caja_y_los_espacios(valor: str):
    """Un LLM que devuelve `"high"` acertó; no hay por qué castigarlo."""
    assert siem_agent._normalizar_severidad(valor, _incidente()) == valor.strip().upper()


@pytest.mark.parametrize(("español", "esperado"),
                         [("critica", "CRITICAL"), ("alta", "HIGH"),
                          ("media", "MEDIUM"), ("baja", "LOW"),
                          ("ALTA", "HIGH")])
def test_se_traducen_las_severidades_en_español(español: str, esperado: str):
    """El clasificador las nombra en español y el LLM responde en español a veces."""
    assert siem_agent._normalizar_severidad(español, _incidente()) == esperado


# ─── Lo que pasa con un valor irreconocible ──────────────────────────────────

@pytest.mark.parametrize("basura", ["urgentísimo", "", "  ", "SEVERE", "9",
                                    None, 42, [], {}, ["HIGH"]])
def test_un_valor_irreconocible_cae_a_la_severidad_deterministica(basura: object):
    assert siem_agent._normalizar_severidad(basura, _incidente("critica")) == "CRITICAL"


@pytest.mark.parametrize(("determinista", "esperado"),
                         [("critica", "CRITICAL"), ("alta", "HIGH"),
                          ("media", "MEDIUM"), ("baja", "LOW")])
def test_el_respaldo_es_la_severidad_del_agente_1(determinista: str, esperado: str):
    assert siem_agent._normalizar_severidad("???", _incidente(determinista)) == esperado


def test_el_respaldo_nunca_degrada_un_incidente_critico():
    """**La razón de no usar MEDIUM como default.**

    Si un LLM devolviera basura en un incidente que el Agente 1 clasificó como
    crítico, caer a MEDIUM lo bajaría dos niveles sin que nadie se enterara. Un
    analista que filtra por severidad dejaría de verlo.
    """
    resultado = siem_agent._normalizar_severidad("¡¡¡MUY GRAVE!!!", _incidente("critica"))
    assert resultado == "CRITICAL", "se degradó un incidente crítico"


def test_sin_clasificacion_usable_queda_medium():
    """Último recurso, cuando no hay nada en qué apoyarse."""
    assert siem_agent._normalizar_severidad(None, {"classification": {}}) == "MEDIUM"
    assert siem_agent._normalizar_severidad(None, {}) == "MEDIUM"


# ─── Todo lo que puede salir, el panel lo sabe pintar ────────────────────────

def test_toda_severidad_posible_tiene_su_clase_en_el_css():
    """El aserto que cierra el círculo con G1: si alguien agrega un valor válido al
    Agente 2 sin agregar su `.b-*`, la insignia sale sin color."""
    assert siem_agent._SEV_VALIDAS <= CLASES_CSS, (
        f"sin regla CSS: {siem_agent._SEV_VALIDAS - CLASES_CSS}")


def test_las_traducciones_del_español_tambien_son_pintables():
    assert set(siem_agent._SEV_MAP.values()) <= CLASES_CSS


# ─── El camino completo, con un LLM que responde mal ─────────────────────────

def _con_llm_que_devuelve(monkeypatch, severidad: object):
    """Sustituye `_llm_analysis` por uno que devuelve la severidad indicada.

    No se simula el cliente de Gemini: el paquete `google` no está instalado en el
    entorno de pruebas y, sobre todo, lo que se verifica es qué hace
    `analyze_incident` con la respuesta — no cómo se obtiene.
    """
    def falso(client, incident, historical, campaign):
        del client, incident, historical, campaign
        return {"explicacion": "x", "metodologia": "x", "contexto_riesgo": "x",
                "severidad_ajustada": severidad, "accion_recomendada": "revisar",
                "falso_positivo_probabilidad": "LOW", "referencias": [],
                "_source": "llm"}

    monkeypatch.setattr(siem_agent, "_llm_analysis", falso)
    return object()  # un cliente cualquiera: alcanza con que no sea None


def test_analyze_incident_normaliza_lo_que_vino_del_llm(monkeypatch):
    cliente = _con_llm_que_devuelve(monkeypatch, "alta")
    analisis = siem_agent.analyze_incident(cliente, _incidente("critica"), "sin antecedentes", None)

    assert analisis["severidad_ajustada"] == "HIGH"
    assert analisis["severidad_ajustada_sin_normalizar"] == "alta", (
        "se corrigió el valor pero no quedó registro de qué había dicho el LLM")


def test_no_se_agrega_ruido_cuando_el_llm_acierta(monkeypatch):
    cliente = _con_llm_que_devuelve(monkeypatch, "HIGH")
    analisis = siem_agent.analyze_incident(cliente, _incidente("alta"), "sin antecedentes", None)

    assert analisis["severidad_ajustada"] == "HIGH"
    assert "severidad_ajustada_sin_normalizar" not in analisis


def test_una_severidad_inventada_por_el_llm_no_degrada_el_incidente(monkeypatch):
    cliente = _con_llm_que_devuelve(monkeypatch, "catastrófica")
    analisis = siem_agent.analyze_incident(cliente, _incidente("critica"),
                                           "sin antecedentes", None)

    assert analisis["severidad_ajustada"] == "CRITICAL"
    assert analisis["severidad_ajustada_sin_normalizar"] == "catastrófica"


def test_el_respaldo_deterministico_ya_venia_normalizado():
    """Sin cliente, `analyze_incident` usa el fallback. No tiene que tocar nada."""
    inc = _incidente("alta")
    analisis = siem_agent.analyze_incident(None, inc, "sin antecedentes", None)

    assert analisis["severidad_ajustada"] in siem_agent._SEV_VALIDAS
    assert "severidad_ajustada_sin_normalizar" not in analisis
