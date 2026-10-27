"""Restricciones de despliegue de la ERS verificadas sobre docker-compose.yml.

- **RQ-SEC-24**: los contenedores de ataque corren bajo un perfil que no arranca
  por defecto y en una red propia, separada de la del SIEM y de la capa IA. Antes
  `ssh-target` y `hydra-attacker` estaban en `elastic-net`, junto a
  Elasticsearch, Kibana y Logstash, y los scripts de simulación lanzaban nmap
  real contra IPs fijas de esa red.
- **RNF-COMP-01 / RNF-RD-02**: todo servicio declara un tope de memoria; los
  microservicios de la capa IA (incluido el Agente 2) no pasan de 256 MB.
- **RNF-CONF-05**: la capa SIEM se verifica cada 30 s y, con 3 fallos, un
  contenedor "unhealthy" se reinicia (Docker solo no lo hace: hace falta autoheal).
- **RQ-SEC-05**: hay un servicio de respaldo y Elasticsearch tiene repositorio
  de snapshots.
- **RNF-MANT-04 / RNF-PORT-05**: umbrales, ventana y cluster salen de `.env`.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent.parent
COMPOSE = (RAIZ / "docker-compose.yml").read_text(encoding="utf-8")


def _servicio(nombre: str) -> str:
    """El bloque YAML de un servicio (sin parsear: no sumamos PyYAML por esto)."""
    partes = re.split(r"\n  (?=[a-z-]+:\n)", COMPOSE.split("\nnetworks:\n")[0])
    for parte in partes:
        if parte.startswith(f"{nombre}:\n"):
            return parte
    raise AssertionError(f"no está el servicio {nombre!r} en docker-compose.yml")


SIMULACION = ("ssh-target", "hydra-attacker")
ELASTIC = ("elasticsearch", "kibana", "logstash", "filebeat")
CAPA_IA = ("auth", "audit", "collector", "classifier", "knowledge", "analyst",
           "pipeline", "gateway")


@pytest.mark.parametrize("nombre", SIMULACION)
def test_la_simulacion_corre_en_su_propia_red_y_no_arranca_sola(nombre):
    bloque = _servicio(nombre)
    assert 'profiles: ["simulation"]' in bloque
    redes = re.search(r"^    networks:\n((?:      - \S+\n)+)", bloque, re.MULTILINE)
    assert redes, f"{nombre} no declara sus redes"
    assert re.findall(r"- (\S+)", redes.group(1)) == ["sim-net"]


def test_sim_net_esta_declarada():
    redes = COMPOSE.split("\nnetworks:\n")[1]
    assert re.search(r"^  sim-net:\n", redes, re.MULTILINE)


@pytest.mark.parametrize("nombre", ELASTIC + CAPA_IA + ("autoheal", "backup"))
def test_todo_servicio_tiene_tope_de_memoria(nombre):
    assert re.search(r"^    mem_limit: \S+", _servicio(nombre), re.MULTILINE), \
        f"{nombre} no declara mem_limit (RNF-COMP-01)"


@pytest.mark.parametrize("nombre", CAPA_IA)
def test_la_capa_ia_no_pasa_de_256_mb(nombre):
    assert re.search(r"^    mem_limit: 256m\b", _servicio(nombre), re.MULTILINE)


@pytest.mark.parametrize("script", ["simulation/run-port-scan.sh", "simulation/run-pentest.sh"])
def test_el_nmap_real_no_apunta_a_ips_fijas_de_la_red_del_siem(script):
    """El escaneo real va contra la víctima del laboratorio, nunca contra un rango
    fijo de la red del SIEM (donde está Elasticsearch)."""
    fuente = (RAIZ / script).read_text(encoding="utf-8")
    lineas_nmap = [linea for linea in fuente.splitlines()
                   if "nmap" in linea and "docker exec" in linea and "install" not in linea]
    assert lineas_nmap
    for linea in lineas_nmap:
        assert "172.18." not in linea, linea
        # TARGET_IP es la IP que va en los logs SINTÉTICOS de run-port-scan.sh
        # (172.18.0.5): no es un objetivo de escaneo real.
        assert '"$TARGET_IP"' not in linea, linea


# ─── RNF-CONF-05: salud cada 30 s y reinicio tras 3 fallos (A4) ──────────────

@pytest.mark.parametrize("nombre", ELASTIC)
def test_la_capa_siem_se_verifica_cada_30_s_con_3_reintentos(nombre):
    bloque = _servicio(nombre)
    salud = re.search(r"^    healthcheck:\n((?:      .+\n)+)", bloque, re.MULTILINE)
    assert salud, f"{nombre} no tiene healthcheck"
    assert "interval: 30s" in salud.group(1)
    assert "retries: 3" in salud.group(1), "3 fallos × 30 s = 90 s (ERS 7.9.3)"
    assert "start_period:" in salud.group(1), "sin margen, el arranque en frío contaría como fallo"


@pytest.mark.parametrize("nombre", ELASTIC + CAPA_IA)
def test_todo_servicio_con_healthcheck_lo_vigila_autoheal(nombre):
    bloque = _servicio(nombre)
    assert "healthcheck:" in bloque
    assert re.search(r"^    labels: \*?autoheal", bloque, re.MULTILINE) or 'autoheal: "true"' in bloque


def test_autoheal_esta_fijado_y_aislado():
    bloque = _servicio("autoheal")
    assert re.search(r"image: willfarrell/autoheal:\d+\.\d+\.\d+\n", bloque), "imagen sin versión fija"
    assert "AUTOHEAL_CONTAINER_LABEL=autoheal" in bloque
    assert "network_mode: none" in bloque, "tiene el socket de Docker: no necesita red"
    assert "ports:" not in bloque


def test_filebeat_espera_a_que_logstash_este_sano():
    assert re.search(r"logstash:\n        condition: service_healthy", _servicio("filebeat"))


# ─── RQ-SEC-05: respaldo (A1) ───────────────────────────────────────────────

def test_elasticsearch_tiene_repositorio_de_snapshots():
    yml = (RAIZ / "elasticsearch" / "elasticsearch.yml").read_text(encoding="utf-8")
    assert 'path.repo: ["/usr/share/elasticsearch/snapshots"]' in yml
    assert "./data/backup/snapshots:/usr/share/elasticsearch/snapshots" in _servicio("elasticsearch")


def test_el_respaldo_lee_la_auditoria_sin_poder_modificarla():
    bloque = _servicio("backup")
    assert "./data/audit:/datos/audit:ro" in bloque
    assert "./data/backup/snapshots:/snapshots" in bloque
    assert "SIEM_RESPALDO_CLAVE=" in bloque
    assert "SIEM_RESPALDO_HORA=${SIEM_RESPALDO_HORA:-03:00}" in bloque


def test_los_respaldos_no_van_al_repositorio():
    assert re.search(r"^data/backup/$", (RAIZ / ".gitignore").read_text(encoding="utf-8"), re.MULTILINE)


# ─── RNF-MANT-04 / RNF-PORT-05: configuración externa (A5) ──────────────────

def test_el_collector_puede_apuntar_a_otro_cluster():
    """Antes ES_HOST estaba fijo: el de .env se ignoraba (pendiente P8)."""
    assert "ES_HOST=${SIEM_ES_HOST:-http://elasticsearch:9200}" in _servicio("collector")


@pytest.mark.parametrize("variable", ["SIEM_UMBRAL_FUERZA_BRUTA", "SIEM_UMBRAL_CRITICO",
                                      "SIEM_UMBRAL_PUERTOS", "SIEM_VENTANA"])
def test_el_clasificador_recibe_umbrales_y_ventana_del_entorno(variable):
    assert f"- {variable}=${{{variable}:-" in _servicio("classifier")


def test_el_collector_usa_la_misma_ventana():
    assert "- SIEM_VENTANA=${SIEM_VENTANA:-24h}" in _servicio("collector")
