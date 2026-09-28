"""Regresión de **B-01 … B-05** — robustez del acceso a datos.

Cinco defectos menores que no tumbaban el sistema, pero que lo hacían mentir:

- **B-01** — `es_search` capturaba `ConnectionError` pero no `ReadTimeout` (que
  no hereda de él). Un Elasticsearch vivo pero saturado producía un traceback en
  vez del mensaje de ayuda, y `prepare-for-ia.py` moría sin preservar la captura.
- **B-02** — Basic Auth sobre HTTP sin `verify=` explícito.
- **B-03** — `first_seen`/`last_seen` se comparaban como texto, con formatos
  mezclados (`…Z` de Elastic vs `+00:00` de `now_iso()`).
- **B-04** — `classifier.main()` leía dos claves que nadie generaba.
- **B-05** — `read_network_logs` leía todo el directorio sin ventana temporal,
  así que cada corrida de la simulación inflaba el mismo incidente.

Reemplazan a los congelados `test_B01_*` … `test_B05_*`.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import requests

import classifier
import siem_lib

# ─── B-01 · todos los fallos de red dan el mismo error accionable ────────────

@pytest.mark.parametrize("excepcion", [
    requests.exceptions.ReadTimeout("tardó demasiado"),
    requests.exceptions.ConnectTimeout("no conectó a tiempo"),
    requests.exceptions.ConnectionError("sin ruta al host"),
    requests.exceptions.TooManyRedirects("bucle de redirecciones"),
    requests.exceptions.ChunkedEncodingError("respuesta truncada"),
    requests.exceptions.RequestException("otra cosa"),
])
def test_todo_fallo_de_red_se_traduce_a_esunavailable(monkeypatch, excepcion):
    """El caller solo necesita saber una cosa: ES no está disponible."""
    monkeypatch.setattr(siem_lib.requests, "post",
                        lambda *a, **kw: (_ for _ in ()).throw(excepcion))
    with pytest.raises(siem_lib.ESUnavailable):
        siem_lib.es_search("filebeat-*", {})


def test_el_read_timeout_explica_qué_pasó(monkeypatch):
    """El mensaje tiene que servirle a quien lo lee a las 3 de la mañana."""
    monkeypatch.setattr(siem_lib.requests, "post", lambda *a, **kw: (_ for _ in ()).throw(
        requests.exceptions.ReadTimeout("timeout")))

    with pytest.raises(siem_lib.ESUnavailable) as error:
        siem_lib.es_search("filebeat-*", {}, timeout=7)
    assert "7s" in str(error.value)
    assert "saturado" in str(error.value)


def test_una_respuesta_no_json_tambien_se_traduce(monkeypatch):
    """Un proxy que devuelve HTML no puede reventar con un error de parseo."""
    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            raise ValueError("no es JSON")

    monkeypatch.setattr(siem_lib.requests, "post", lambda *a, **kw: Resp())
    with pytest.raises(siem_lib.ESUnavailable, match="no-JSON"):
        siem_lib.es_search("filebeat-*", {})


def test_es_aggregate_comparte_el_mismo_manejo(monkeypatch):
    """R-01: antes cada función manejaba los errores a su manera.

    `es_aggregate` se tragaba los HTTPError devolviendo `[]`, así que un 401 por
    credenciales vencidas se veía igual que "no hay datos".
    """
    monkeypatch.setattr(siem_lib.requests, "post", lambda *a, **kw: (_ for _ in ()).throw(
        requests.exceptions.ReadTimeout("timeout")))
    with pytest.raises(siem_lib.ESUnavailable):
        siem_lib.es_aggregate("filebeat-*", {}, "by_source_ip")


def test_un_indice_inexistente_sigue_sin_ser_fatal(monkeypatch):
    """404 significa "todavía no hay datos", no un error."""
    class Resp:
        status_code = 404

        def raise_for_status(self):
            raise requests.exceptions.HTTPError("404", response=self)

        def json(self):
            return {}

    monkeypatch.setattr(siem_lib.requests, "post", lambda *a, **kw: Resp())
    assert siem_lib.es_search("filebeat-*", {}) == []
    assert siem_lib.es_aggregate("filebeat-*", {}, "by_source_ip") == []


# ─── B-02 · credenciales en claro solo dentro de la máquina ──────────────────

@pytest.mark.parametrize("host", [
    "http://localhost:9200", "http://127.0.0.1:9200", "http://[::1]:9200",
])
def test_http_a_loopback_esta_permitido(monkeypatch, host):
    """Es la configuración por defecto: los puertos están bindeados a 127.0.0.1
    y las credenciales nunca salen del host."""
    monkeypatch.setattr(siem_lib, "ES_HOST", host)
    siem_lib._verificar_transporte()  # no levanta


@pytest.mark.parametrize("host", [
    "http://192.168.1.50:9200", "http://elastic.interno:9200", "http://10.0.0.5:9200",
])
def test_http_a_un_host_remoto_se_bloquea(monkeypatch, host):
    """Apuntar ES_HOST a otra máquina por HTTP expondría el Basic Auth en la red."""
    monkeypatch.setattr(siem_lib, "ES_HOST", host)
    monkeypatch.setattr(siem_lib, "ES_ALLOW_INSECURE_HTTP", False)
    with pytest.raises(siem_lib.ESInsecureTransport, match="en claro"):
        siem_lib._verificar_transporte()


def test_https_remoto_esta_permitido(monkeypatch):
    monkeypatch.setattr(siem_lib, "ES_HOST", "https://elastic.interno:9200")
    siem_lib._verificar_transporte()


def test_la_escotilla_de_escape_es_explicita(monkeypatch):
    """Un laboratorio aislado puede optar por HTTP, pero tiene que decirlo."""
    monkeypatch.setattr(siem_lib, "ES_HOST", "http://192.168.1.50:9200")
    monkeypatch.setattr(siem_lib, "ES_ALLOW_INSECURE_HTTP", True)
    siem_lib._verificar_transporte()


def test_las_peticiones_pasan_verify(monkeypatch):
    """`verify=` explícito: antes quedaba en el default implícito de requests."""
    capturado = {}

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return {"hits": {"hits": []}}

    def post(*args, **kwargs):
        capturado.update(kwargs)
        return Resp()

    monkeypatch.setattr(siem_lib.requests, "post", post)
    siem_lib.es_search("filebeat-*", {})
    assert "verify" in capturado
    assert "timeout" in capturado


# ─── B-03 · timestamps comparados como instantes ─────────────────────────────

def test_los_dos_formatos_son_el_mismo_instante():
    """`…Z` de Elasticsearch y `+00:00` de `now_iso()`."""
    z = siem_lib.parse_ts("2026-09-16T10:00:00.000Z")
    offset = siem_lib.parse_ts("2026-09-16T10:00:00.000+00:00")
    assert z == offset
    # Como texto decían lo contrario: 'Z' (0x5A) ordena después de '+' (0x2B).
    assert "2026-09-16T10:00:00.000Z" > "2026-09-16T10:00:00.000+00:00"


@pytest.mark.parametrize("valor", [None, "", "   ", "no es fecha", 42, [], {}])
def test_parse_ts_devuelve_none_ante_basura(valor):
    assert siem_lib.parse_ts(valor) is None


def test_parse_ts_asume_utc_si_no_hay_zona():
    parseado = siem_lib.parse_ts("2026-09-16T10:00:00")
    assert parseado.tzinfo is not None
    assert parseado.utcoffset() == timedelta(0)


def test_ts_ordenable_no_rompe_un_sorted():
    """Un timestamp roto no puede tumbar el ordenamiento de toda la evidencia."""
    valores = ["2026-09-16T12:00:00Z", None, "basura", "2026-09-16T08:00:00+00:00"]
    ordenados = sorted(valores, key=siem_lib.ts_ordenable)
    assert ordenados[-1] == "2026-09-16T12:00:00Z"
    assert ordenados[-2] == "2026-09-16T08:00:00+00:00"


def test_first_seen_y_last_seen_con_formatos_mezclados():
    """El caso real: alertas con `Z` y logs con offset en el mismo incidente."""
    datos = {
        "alerts": [{"timestamp": "2026-09-16T08:00:00.000Z", "source_ip": "203.0.113.7",
                    "rule_name": "SSH Brute Force", "event_count": 3,
                    "mitre": {"technique_id": "T1110"}}],
        "auth_failure_logs": [{
            "timestamp": "2026-09-16T12:00:00.000+00:00",
            "message": "Failed password for testuser from 203.0.113.7 port 40000 ssh2",
            "host_ip": "172.18.0.7"}],
    }
    inc = classifier.detect_auth_incidents(datos)[0]
    assert siem_lib.parse_ts(inc["first_seen"]) < siem_lib.parse_ts(inc["last_seen"])
    assert "08:00" in inc["first_seen"]
    assert "12:00" in inc["last_seen"]


# ─── B-04 · sin ramas muertas en la orquestación ─────────────────────────────

def test_ya_no_se_leen_claves_inexistentes():
    """`network_events` y `web_events` nunca las generó `prepare-for-ia.py`."""
    fuente = Path(classifier.__file__).read_text(encoding="utf-8")
    cuerpo = fuente.split("def main()")[1]
    assert 'get("network_events"' not in cuerpo
    assert 'get("web_events"' not in cuerpo


def test_prepare_for_ia_sigue_sin_generarlas(siem_clean):
    """Blindaje: si alguna vez se implementa la extracción, este test avisa."""
    assert "network_events" not in siem_clean
    assert "web_events" not in siem_clean


# ─── B-05 · retención de los logs de simulación ──────────────────────────────

def _evento(ts: datetime, puerto: int) -> str:
    return json.dumps({
        "@timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "event_type": "network_flow", "source_ip": "203.0.113.7",
        "dest_ip": "10.0.0.5", "dest_port": puerto, "protocol": "tcp"})


def test_los_eventos_viejos_quedan_fuera_de_la_ventana(sandbox):
    """Corridas anteriores ya no inflan el incidente de hoy."""
    ahora = datetime.now(timezone.utc)
    viejo = ahora - timedelta(hours=48)
    destino = sandbox / "network_logs"

    (destino / "corrida-vieja.json").write_text(
        "\n".join(_evento(viejo, p) for p in range(1, 27)) + "\n", encoding="utf-8")
    (destino / "corrida-nueva.json").write_text(
        "\n".join(_evento(ahora, p) for p in range(1, 27)) + "\n", encoding="utf-8")

    eventos = siem_lib.read_network_logs(destino)
    assert len(eventos) == 26, "se leyeron también los de hace 48 h"

    incidentes = classifier.detect_port_scans(eventos)
    assert incidentes[0]["event_count"] == 26, "antes daba 52"


def test_la_ventana_se_puede_desactivar_para_forense(sandbox):
    ahora = datetime.now(timezone.utc)
    destino = sandbox / "network_logs"
    (destino / "vieja.json").write_text(
        _evento(ahora - timedelta(days=30), 22) + "\n", encoding="utf-8")

    assert siem_lib.read_network_logs(destino) == []
    assert len(siem_lib.read_network_logs(destino, window_hours=None)) == 1


def test_un_evento_sin_timestamp_se_conserva(sandbox):
    """Descartarlo en silencio sería peor que analizarlo de más."""
    destino = sandbox / "network_logs"
    (destino / "sin-ts.json").write_text(
        json.dumps({"event_type": "network_flow", "source_ip": "203.0.113.7",
                    "dest_port": 22}) + "\n", encoding="utf-8")
    assert len(siem_lib.read_network_logs(destino)) == 1


def test_la_ventana_coincide_con_la_de_elasticsearch():
    """Las dos fuentes tienen que mirar el mismo período o el conteo miente."""
    import inspect
    firma = inspect.signature(siem_lib.read_network_logs)
    assert firma.parameters["window_hours"].default == 24

    rango = siem_lib.auth_failure_query(10)["query"]["bool"]["filter"][0]
    assert rango["range"]["@timestamp"]["gte"] == "now-24h"


def test_una_linea_malformada_sigue_sin_cortar_la_lectura(sandbox):
    """Un log sucio no puede impedir que se detecte el resto del ataque."""
    destino = sandbox / "network_logs"
    ahora = datetime.now(timezone.utc)
    lineas = [_evento(ahora, 22), "{esto no es json", _evento(ahora, 80)]
    (destino / "sucio.json").write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert len(siem_lib.read_network_logs(destino)) == 2


# ─── Guarda contra una fragilidad que solo aparece al día siguiente ──────────

# Marca para eximir una línea que usa la ventana por defecto a propósito.
MARCA_EXCEPCION = "ventana-ok"

def test_ningun_test_lee_un_fixture_con_la_ventana_por_defecto():
    """Los fixtures tienen fecha fija; la ventana de 24 h los descarta mañana.

    Esta prueba existe porque el problema ya ocurrió: la ventana que introdujo
    B-05 rompió cuatro pruebas de S-01 y S-02 al cambiar la fecha, sin que nadie
    tocara una línea de código. Una suite que depende del día en que se corre no
    es una red de seguridad — es un aviso que llega tarde y por el motivo
    equivocado.

    Regla: todo test que lea un fixture del repositorio pasa por
    `tests.conftest.eventos_de_red()`, que desactiva la ventana. Los tests DEL
    filtro generan sus eventos relativos a `datetime.now()`.
    """
    raiz = Path(__file__).resolve().parent.parent
    infractores = []

    for archivo in raiz.rglob("test_*.py"):  # ventana-ok: es esta misma guarda
        for numero, linea in enumerate(archivo.read_text(encoding="utf-8").splitlines(), 1):
            # ventana-ok: esta línea es la que detecta, no una lectura de fixture.
            if "read_network_logs(" not in linea or linea.strip().startswith("#"):  # ventana-ok
                continue
            # Permitido: ventana explícita; directorio que el propio test acabó de
            # escribir (sandbox/destino); o marcado como excepción deliberada.
            if any(ok in linea for ok in
                   ("window_hours", "sandbox", "destino", MARCA_EXCEPCION)):
                continue
            infractores.append(f"{archivo.relative_to(raiz)}:{numero}: {linea.strip()}")

    assert not infractores, (
        "Estos tests leen un fixture con la ventana de 24 h activa y van a fallar "
        "cuando el fixture tenga más de un día. Usá `eventos_de_red()`:\n  "
        + "\n  ".join(infractores))


def test_los_fixtures_del_repositorio_ya_son_viejos():
    """Confirma que la guarda anterior no es teórica.

    Si los fixtures fueran de hoy, el test de arriba pasaría por casualidad. Este
    verifica que efectivamente ya caen fuera de la ventana, que es la condición
    en la que el problema se manifiesta.
    """
    import siem_lib

    fixtures = Path(__file__).resolve().parent.parent / "fixtures" / "malicious"
    assert siem_lib.read_network_logs(fixtures) == [], "ventana-ok: caso a propósito"
    assert len(siem_lib.read_network_logs(fixtures, window_hours=None)) == 2
