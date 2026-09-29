"""Catálogo de reglas de detección versionado (hallazgo **F-02**, `RF-DIF-03`).

`rules/rules.md` documentaba 13 reglas, pero en el Kibana que corría había 4,
creadas a mano en la consola. **Quien clonaba el repositorio y levantaba el
stack no obtenía el mismo sistema**, y eso rompe la reproducibilidad — que es
justamente lo que evalúa el objetivo del entorno de simulación.

Ahora las 13 viven en `rules/ndjson/`, una por archivo, y se despliegan con
`./scripts/deploy-rules.sh`.

> **Detectar no es actuar.** Estas reglas le enseñan a Elastic qué reconocer en
> los logs. Ninguna ejecuta nada: `test_ninguna_regla_dispara_acciones` lo
> comprueba, y la no-autonomía del sistema sigue certificada aparte en
> `tests/test_no_autonomy.py`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DIR_REGLAS = PROJECT_ROOT / "rules" / "ndjson"
CATALOGO_MD = PROJECT_ROOT / "rules" / "rules.md"

# Campos que Kibana genera en cada instalación: si aparecieran en un archivo
# versionado, el repositorio quedaría atado a una instalación concreta.
VOLATILES = {"id", "created_at", "created_by", "updated_at", "updated_by",
             "revision", "execution_summary"}


def _archivos() -> list[Path]:
    return sorted(DIR_REGLAS.glob("*.ndjson"))


def _reglas() -> dict[str, dict]:
    return {p.name: json.loads(p.read_text(encoding="utf-8")) for p in _archivos()}


def _codigos_del_catalogo() -> dict[str, str]:
    """Lee la tabla resumen de `rules.md`: {código: nombre}."""
    texto = CATALOGO_MD.read_text(encoding="utf-8")
    codigos = {}
    for linea in texto.splitlines():
        m = re.match(r"^\|\s*([ABC]\d)\s*\|\s*([^|]+?)\s*\|", linea)
        if m:
            codigos[m.group(1)] = m.group(2).strip()
    return codigos


@pytest.fixture(scope="module")
def reglas() -> dict[str, dict]:
    return _reglas()


# ─── El catálogo está completo ───────────────────────────────────────────────

def test_hay_catorce_reglas():
    """Las 14 del catálogo, ni una menos."""
    assert len(_archivos()) == 14


def test_cada_regla_del_catalogo_tiene_su_archivo():
    """Compara contra `rules.md`, que es la fuente documental del catálogo.

    Si alguien agrega una regla al documento y se olvida del archivo (o al
    revés), esto lo detecta: era exactamente la brecha F-02.
    """
    codigos_md = _codigos_del_catalogo()
    assert len(codigos_md) == 14, f"rules.md declara {len(codigos_md)} reglas"

    codigos_archivos = {p.name.split("-", 1)[0] for p in _archivos()}
    faltan = set(codigos_md) - codigos_archivos
    sobran = codigos_archivos - set(codigos_md)

    assert not faltan, f"sin archivo versionado: {sorted(faltan)}"
    assert not sobran, f"archivos sin entrada en rules.md: {sorted(sobran)}"


def test_el_nombre_coincide_con_el_del_catalogo(reglas):
    """El nombre del archivo y el `name` de la regla dicen lo mismo que rules.md."""
    codigos_md = _codigos_del_catalogo()
    for nombre_archivo, regla in reglas.items():
        codigo = nombre_archivo.split("-", 1)[0]
        assert regla["name"] == codigos_md[codigo], (
            f"{nombre_archivo}: se llama '{regla['name']}' pero rules.md dice "
            f"'{codigos_md[codigo]}'")


# ─── Cada archivo es válido ──────────────────────────────────────────────────

@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_el_archivo_es_ndjson_de_una_sola_regla(archivo):
    contenido = archivo.read_text(encoding="utf-8")
    assert contenido.endswith("\n"), "NDJSON: cada línea termina en salto"
    assert contenido.count("\n") == 1, "una regla por archivo"
    json.loads(contenido)  # levanta si no es JSON válido


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_el_archivo_trae_los_campos_obligatorios(archivo):
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    for campo in ("rule_id", "name", "type", "severity", "risk_score", "threat",
                  "description", "index", "interval", "from", "enabled"):
        assert campo in regla, f"falta '{campo}'"


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_el_archivo_no_lleva_campos_de_una_instalacion(archivo):
    """`id`, `created_at`… los genera Kibana: versionarlos ata el repo a una
    instalación y produce un diff en cada exportación."""
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    presentes = VOLATILES & set(regla)
    assert not presentes, f"campos volátiles versionados: {sorted(presentes)}"


def test_los_rule_id_son_unicos(reglas):
    """El `rule_id` es la identidad de la regla: repetirlo haría que un import
    pisara la otra en silencio."""
    ids = [r["rule_id"] for r in reglas.values()]
    assert len(ids) == len(set(ids)), f"rule_id duplicado: {ids}"


def test_el_rule_id_coincide_con_el_nombre_del_archivo(reglas):
    """`A3-ssh-invalid-user-enumeration.ndjson` ⇒ `ssh-invalid-user-enumeration`."""
    for nombre_archivo, regla in reglas.items():
        esperado = nombre_archivo.removesuffix(".ndjson").split("-", 1)[1]
        assert regla["rule_id"] == esperado


# ─── Coherencia del contenido ────────────────────────────────────────────────

@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_la_regla_apunta_al_indice_del_proyecto(archivo):
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    assert regla["index"] == ["filebeat-*"]


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_la_regla_declara_su_tecnica_mitre(archivo):
    """Sin mapeo MITRE, el clasificador no puede correlacionar la alerta."""
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    assert regla["threat"], "sin mapeo MITRE"

    for amenaza in regla["threat"]:
        assert amenaza["framework"] == "MITRE ATT&CK"
        assert amenaza["tactic"]["id"].startswith("TA")
        assert amenaza["technique"], "táctica sin técnica"
        for tecnica in amenaza["technique"]:
            assert re.match(r"^T\d{4}$", tecnica["id"]), tecnica["id"]


def test_se_cubren_las_tres_tecnicas_del_proyecto(reglas):
    """T1110 (fuerza bruta), T1046 (escaneo) y T1566 (phishing)."""
    tecnicas = {t["id"] for r in reglas.values() for a in r["threat"]
                for t in a["technique"]}
    assert {"T1110", "T1046", "T1566"} <= tecnicas


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_la_severidad_y_el_riesgo_son_coherentes(archivo):
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    assert regla["severity"] in ("low", "medium", "high", "critical")
    assert 0 <= regla["risk_score"] <= 100

    rangos = {"low": (0, 47), "medium": (21, 73), "high": (47, 99),
              "critical": (73, 100)}
    minimo, maximo = rangos[regla["severity"]]
    assert minimo <= regla["risk_score"] <= maximo, (
        f"severidad '{regla['severity']}' con riesgo {regla['risk_score']}")


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_la_ventana_de_busqueda_cubre_el_intervalo(archivo):
    """`from` tiene que mirar al menos tan atrás como dura el intervalo, o la
    regla deja huecos entre ejecuciones y pierde eventos."""
    regla = json.loads(archivo.read_text(encoding="utf-8"))

    def minutos(texto: str) -> int:
        m = re.match(r"^(?:now-)?(\d+)([smh])$", texto)
        assert m, f"formato inesperado: {texto}"
        valor, unidad = int(m.group(1)), m.group(2)
        return valor * {"s": 1 / 60, "m": 1, "h": 60}[unidad]

    assert minutos(regla["from"]) >= minutos(regla["interval"]), (
        f"from={regla['from']} no cubre interval={regla['interval']}")


# ─── El mapeo del índice: `.keyword` donde hace falta ────────────────────────

CAMPOS_TEXT = ("source_ip", "tags", "user", "dest_ip", "host.ip",
               "event_type", "http_method")


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_los_campos_de_agrupacion_usan_keyword(archivo):
    """Agrupar por un campo `text` falla con "Fielddata is disabled".

    En `filebeat-*`, `source_ip`, `tags`, `user`, `dest_ip`, `host.ip`,
    `event_type` y `http_method` están mapeados como `text`. El catálogo de
    `rules.md` los nombra sin sufijo (es la vista del asistente de Kibana), pero
    una regla threshold que agrupe por `source_ip` a secas **no corre**. Este
    test evita que una regla nueva repita el error.
    """
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    umbral = regla.get("threshold")
    if not umbral:
        return

    campos = list(umbral.get("field") or [])
    campos += [c["field"] for c in umbral.get("cardinality") or []]

    for campo in campos:
        base = campo.removesuffix(".keyword")
        if base in CAMPOS_TEXT:
            assert campo.endswith(".keyword"), (
                f"'{campo}' es un campo text: agrupar por él falla. "
                f"Usar '{base}.keyword'.")


@pytest.mark.parametrize("archivo", _archivos(), ids=lambda p: p.name)
def test_las_reglas_eql_agrupan_por_keyword(archivo):
    regla = json.loads(archivo.read_text(encoding="utf-8"))
    if regla["type"] != "eql":
        return

    for campo in re.findall(r"sequence by ([\w.]+)", regla["query"]):
        base = campo.removesuffix(".keyword")
        if base in CAMPOS_TEXT:
            assert campo.endswith(".keyword"), f"'{campo}' debería ser keyword"


# ─── No-autonomía: una detección no dispara nada ─────────────────────────────

def test_ninguna_regla_dispara_acciones(reglas):
    """**La propiedad rectora, en la capa del SIEM.**

    El campo `actions` de una regla de Elastic es donde se conectan webhooks,
    correos o integraciones que se ejecutan solas al saltar una alerta. Todas
    las reglas del catálogo lo tienen vacío: una detección produce una alerta y
    nada más. La cadena sigue terminando en un analista que decide.
    """
    for nombre_archivo, regla in reglas.items():
        assert regla.get("actions", []) == [], (
            f"{nombre_archivo} tiene acciones automáticas: {regla['actions']}")
        assert not regla.get("throttle"), f"{nombre_archivo} declara throttle de acciones"


def test_ninguna_regla_menciona_ejecucion_o_contencion(reglas):
    """Ni por descuido en un nombre, una descripción o una nota."""
    prohibidas = ("ufw ", "iptables", "firewall-cmd", "subprocess", "os.system",
                  "curl -X POST http", "bash -c")
    for nombre_archivo, regla in reglas.items():
        texto = json.dumps(regla, ensure_ascii=False).lower()
        for termino in prohibidas:
            assert termino not in texto, f"{nombre_archivo} menciona '{termino}'"


# ─── Los scripts ─────────────────────────────────────────────────────────────

def test_el_script_de_despliegue_existe_y_es_ejecutable():
    script = PROJECT_ROOT / "scripts" / "deploy-rules.sh"
    assert script.is_file()
    assert script.stat().st_mode & 0o111, "no es ejecutable"


def test_el_despliegue_es_idempotente_por_construccion():
    """`overwrite=true` + `rule_id` fijo: reimportar actualiza, no duplica."""
    script = (PROJECT_ROOT / "scripts" / "deploy-rules.sh").read_text(encoding="utf-8")
    assert "overwrite=true" in script


def test_los_scripts_no_imprimen_credenciales():
    """La contraseña sale de `.env` y no puede terminar en la salida ni en el
    listado de procesos."""
    for nombre in ("deploy-rules.sh", "export-rules.sh"):
        script = (PROJECT_ROOT / "scripts" / nombre).read_text(encoding="utf-8")
        assert "ELASTIC_PASSWORD" not in script.replace(
            "grep -E '^ELASTIC_PASSWORD=' .env", "").replace(
            "ELASTIC_PASSWORD no está definida", "")
        for linea in script.splitlines():
            limpia = linea.strip()
            if limpia.startswith("echo") and "$ES_PASS" in limpia:
                pytest.fail(f"{nombre} imprime la contraseña: {limpia}")


def test_los_scripts_no_ejecutan_nada_sobre_la_infraestructura():
    """`deploy` acá significa "subir reglas de detección", no actuar sobre hosts."""
    for nombre in ("deploy-rules.sh", "export-rules.sh"):
        script = (PROJECT_ROOT / "scripts" / nombre).read_text(encoding="utf-8")
        for peligro in ("ufw ", "iptables", "ssh ", "docker exec", "systemctl"):
            assert peligro not in script, f"{nombre} usa '{peligro}'"

    # Y lo dice en voz alta, para que nadie lo confunda al leerlo.
    despliegue = (PROJECT_ROOT / "scripts" / "deploy-rules.sh").read_text(encoding="utf-8")
    assert "no ejecuta" in despliegue.lower() or "NO ejecuta" in despliegue


def test_start_sh_despliega_las_reglas():
    """Levantar el stack desde cero deja las 13 reglas activas, sin consola."""
    start = (PROJECT_ROOT / "scripts" / "start.sh").read_text(encoding="utf-8")
    assert "deploy-rules.sh" in start
    assert "SIEM_SKIP_RULES" in start, "tiene que poder saltearse"


# ─── El catálogo y los archivos no pueden separarse ──────────────────────────
#
# `rules/rules.md` es la tabla que lee una persona; `rules/ndjson/` es lo que se
# despliega. Cuando se separan, gana el archivo y la documentación miente en
# silencio — y ya había pasado: A2 estaba documentada con umbral ≥10 y desplegada
# con 3, lo que además invertía la escalera de severidad (disparaba una alerta
# *high* antes que A1, que es *medium* con umbral 5).

def _umbrales_documentados() -> dict[str, int]:
    """`| A2 | … | ≥10 fallos por source_ip en 1 min |` → {"A2": 10}."""
    filas = re.findall(
        r"^\|\s*([ABC]\d)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|\s*([^|]+?)\s*\|$",
        CATALOGO_MD.read_text(encoding="utf-8"), re.M)
    fuera = {}
    for identificador, descripcion in filas:
        m = re.search(r"≥(\d+)", descripcion)
        if m:
            fuera[identificador] = int(m.group(1))
    return fuera


def _umbral_desplegado(regla: dict) -> int | None:
    """El número que hace disparar la regla: la cardinalidad si la hay, si no el valor.

    B1 y B2 cuentan valores DISTINTOS (puertos, hosts), así que su umbral vive en
    `threshold.cardinality`; las demás cuentan eventos y usan `threshold.value`.
    """
    umbral = regla.get("threshold") or {}
    cardinalidad = (umbral.get("cardinality") or [{}])[0].get("value")
    return cardinalidad if cardinalidad is not None else umbral.get("value")


def test_el_catalogo_documenta_un_umbral_por_cada_regla_que_lo_tiene():
    """Blindaje del andamiaje: si la tabla cambia de forma, la prueba de abajo
    pasaría por no encontrar nada que comparar."""
    documentados = _umbrales_documentados()
    assert len(documentados) >= 8, f"solo leí {len(documentados)} umbrales de rules.md"


@pytest.mark.parametrize("archivo", sorted((PROJECT_ROOT / "rules" / "ndjson").glob("*.ndjson")),
                         ids=lambda p: p.stem[:2])
def test_el_umbral_desplegado_es_el_que_documenta_el_catalogo(archivo: Path):
    """**La prueba que cierra la brecha entre la tabla y lo que se despliega.**

    Solo compara las reglas que documentan un `≥N`: A4 (EQL), B3 (consulta), B4 y
    C1/C3 (secuencia) no tienen un umbral numérico que contrastar.
    """
    identificador = archivo.stem[:2]
    documentado = _umbrales_documentados().get(identificador)
    if documentado is None:
        pytest.skip(f"{identificador} no documenta un umbral numérico")

    regla = json.loads(archivo.read_text(encoding="utf-8").splitlines()[0])
    desplegado = _umbral_desplegado(regla)

    assert desplegado == documentado, (
        f"{identificador} «{regla['name']}»: rules.md dice ≥{documentado} y el "
        f"archivo despliega {desplegado}. Gana el archivo, así que la tabla mentiría.")


def test_la_escalera_de_severidad_no_se_invierte():
    """A1 es *medium* con umbral 5 y A2 es *high* con umbral 10: una alerta más
    grave tiene que exigir más evidencia, no menos.

    Con A2 en 3 —como estaba desplegada— tres contraseñas mal tipeadas producían una
    alerta de severidad alta antes de que A1 llegara a su umbral.
    """
    def regla(identificador: str) -> dict:
        archivo = next((PROJECT_ROOT / "rules" / "ndjson").glob(f"{identificador}-*.ndjson"))
        return json.loads(archivo.read_text(encoding="utf-8").splitlines()[0])

    a1, a2, a5 = regla("A1"), regla("A2"), regla("A5")
    orden = [(a1, "medium"), (a2, "high"), (a5, "critical")]

    for r, severidad_esperada in orden:
        assert r["severity"] == severidad_esperada, f"{r['name']} cambió de severidad"

    umbrales = [_umbral_desplegado(r) for r, _ in orden]
    assert umbrales == sorted(umbrales), (
        f"la escalera se invirtió: medium={umbrales[0]}, high={umbrales[1]}, "
        f"critical={umbrales[2]}. Una alerta más grave no puede exigir menos evidencia.")
