"""Las agregaciones sobre `filebeat-*` usan `.keyword` (**D-12**).

No hay plantilla de índice para `filebeat-*`: el mapeo es dinámico, así que cada
campo de texto queda como `text` con un subcampo `keyword`. Agregar o ordenar sobre
el `text` devuelve:

    Fielddata is disabled on [source_ip] in [filebeat-8.12.2-...]

que es un **HTTP 400** y aborta la captura entera de Elasticsearch.

El catálogo de reglas ya documentaba esta trampa —se corrigió en la tarea P3, donde
las reglas pasaron a agrupar por `source_ip.keyword`—, pero `siem_lib` quedó afuera:
las reglas son datos y esto es código, y la corrección no cruzó la frontera.

**Por qué no se había notado.** Los índices que ya existían venían de antes y el
pipeline arrastraba un `siem_clean.json` de una captura vieja: como
`prepare-for-ia.py` está marcado como etapa tolerable, el orquestador seguía con los
datos existentes y terminaba con código 0. Todo *parecía* andar.

Apareció al construir la demostración desde cero (`scripts/demo-desde-cero.sh`), que
borra los índices: con `filebeat-*` recién creado, el pipeline dejó de capturar del
SIEM y clasificó solo desde `network_logs/` — sin un solo incidente de autenticación
y sin una sola procedencia «Elastic SIEM».
"""

from __future__ import annotations

import re

import pytest

import siem_lib

# Campos que YA son `keyword` en su índice y no llevan sufijo. Las alertas las
# escribe el motor de detección de Kibana, con mapeo explícito.
CAMPOS_YA_KEYWORD = {"kibana.alert.rule.name"}


def _campos_de_agregacion(consulta: dict) -> list[str]:
    """Todo `terms.field` que aparezca en la consulta, a cualquier profundidad."""
    encontrados = []

    def recorrer(nodo):
        if isinstance(nodo, dict):
            if "terms" in nodo and isinstance(nodo["terms"], dict):
                campo = nodo["terms"].get("field")
                if isinstance(campo, str):
                    encontrados.append(campo)
            for valor in nodo.values():
                recorrer(valor)
        elif isinstance(nodo, list):
            for valor in nodo:
                recorrer(valor)

    recorrer(consulta)
    return encontrados


# ─── La agregación que rompía ────────────────────────────────────────────────

def test_la_agregacion_por_ip_origen_usa_keyword():
    """**El defecto, en una prueba.**

    Sin `.keyword`, esta consulta devuelve 400 y se pierde toda la captura del
    SIEM: alertas, logs de autenticación y el historial por IP.
    """
    campos = _campos_de_agregacion(siem_lib.source_ip_aggregation())

    assert campos == ["source_ip.keyword"], (
        f"agregación sobre {campos}: en filebeat-* eso es un campo `text` y "
        f"Elasticsearch responde «Fielddata is disabled»")


def test_la_agregacion_sigue_devolviendo_el_mismo_bucket():
    """`.keyword` no cambia las claves: siguen siendo las IP, que es lo que
    `build_summary` pone en `top_source_ips`."""
    consulta = siem_lib.source_ip_aggregation()
    assert "by_source_ip" in consulta["aggs"], "cambió el nombre de la agregación"
    assert consulta["size"] == 0


# ─── La regla general, para que no vuelva por otro lado ──────────────────────

@pytest.mark.parametrize("constructor", [
    siem_lib.source_ip_aggregation,
    siem_lib.alerts_query_por_regla,
])
def test_ninguna_agregacion_usa_un_campo_de_texto_sin_sufijo(constructor):
    """Barrido sobre las consultas que construye `siem_lib`.

    Un campo sin `.keyword` que no esté en la lista de los mapeados explícitamente
    queda señalado. Es la prueba que atrapa la próxima agregación que alguien
    agregue sin acordarse del mapeo dinámico.
    """
    sospechosos = [c for c in _campos_de_agregacion(constructor())
                   if not c.endswith(".keyword") and c not in CAMPOS_YA_KEYWORD]

    assert not sospechosos, (
        f"{constructor.__name__} agrega sobre {sospechosos} sin `.keyword`. "
        f"Si el campo es keyword por mapeo explícito, sumalo a CAMPOS_YA_KEYWORD "
        f"con su razón; si no, va con sufijo.")


def test_el_codigo_fuente_no_deja_agregaciones_sin_sufijo():
    """Mira el texto además de las consultas construidas: una agregación nueva
    dentro de una función que estas pruebas no llaman igual queda señalada."""
    import inspect

    fuente = inspect.getsource(siem_lib)
    campos = re.findall(r'"terms":\s*\{"field":\s*"([^"]+)"', fuente)
    campos += re.findall(r'"field":\s*"([^"]+)",\s*"size"', fuente)

    sospechosos = {c for c in campos
                   if not c.endswith(".keyword") and c not in CAMPOS_YA_KEYWORD
                   and not c.startswith("kibana.")}

    assert not sospechosos, f"agregaciones sin `.keyword` en siem_lib: {sospechosos}"


# ─── El catálogo de reglas, que ya lo había corregido ────────────────────────

def test_las_reglas_del_catalogo_tambien_agrupan_por_keyword():
    """P3 corrigió esto en las reglas. Se verifica junto para que quede a la vista
    que es el MISMO defecto a los dos lados de la frontera código/datos."""
    import json
    from pathlib import Path

    raiz = Path(__file__).resolve().parent.parent.parent
    archivos = sorted((raiz / "rules" / "ndjson").glob("*.ndjson"))
    assert archivos, "no encontré el catálogo de reglas"

    for archivo in archivos:
        regla = json.loads(archivo.read_text(encoding="utf-8").splitlines()[0])
        for campo in (regla.get("threshold") or {}).get("field") or []:
            assert campo.endswith(".keyword"), (
                f"{archivo.name} agrupa por «{campo}» sin `.keyword`")
