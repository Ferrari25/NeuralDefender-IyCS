#!/usr/bin/env python3
"""
Cliente de Elasticsearch del servicio collector.

Antes vivía en `siem_lib.py` y lo importaban todos los módulos; ahora es
exclusivo del collector, que es el único servicio con credenciales de
Elasticsearch (y el único conectado a la red del stack Elastic).
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()

# ─── Configuración (desde el entorno) ────────────────────────────────────────

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ELASTIC_PASSWORD", "elastic123")

# B-02: verificación de TLS. `ES_CA_CERT` apunta a la CA del proyecto
# (elasticsearch/certs/ca.crt) cuando se habilite HTTPS en la capa HTTP; hoy el
# stack solo tiene TLS en el transporte (nodo-a-nodo), no en la API REST.
ES_CA_CERT = os.getenv("ES_CA_CERT") or None
ES_VERIFY_TLS: bool | str = ES_CA_CERT or (os.getenv("ES_VERIFY_TLS", "true").lower() != "false")
# Escotilla de escape explícita para un laboratorio que exponga ES sin TLS.
ES_ALLOW_INSECURE_HTTP = os.getenv("ES_ALLOW_INSECURE_HTTP", "false").lower() == "true"

LOGS_INDEX   = "filebeat-*"
ALERTS_INDEX = ".alerts-security.alerts-default"

_AUTH    = HTTPBasicAuth(ES_USER, ES_PASS)
_HEADERS = {"Content-Type": "application/json"}


# ─── Acceso a Elasticsearch ──────────────────────────────────────────────────

class ESUnavailable(RuntimeError):
    """Elasticsearch no está accesible (stack apagado o credenciales inválidas)."""


class ESInsecureTransport(RuntimeError):
    """Se intentó mandar credenciales en claro hacia un host que no es loopback."""


def _es_host_es_loopback(host: str) -> bool:
    nombre = urlparse(host).hostname or ""
    if nombre == "localhost":
        return True
    try:
        return ipaddress.ip_address(nombre).is_loopback
    except ValueError:
        return False


def _verificar_transporte() -> None:
    """B-02: no mandar Basic Auth en claro fuera de la máquina local.

    El stack tiene TLS en el transporte (nodo-a-nodo) pero no en la API REST, y
    los puertos están bindeados a 127.0.0.1, así que en la configuración por
    defecto las credenciales nunca salen del host. Apuntar `ES_HOST` a otra
    máquina por HTTP sí las expondría en la red — eso se bloquea acá, y se
    habilita a propósito con `ES_ALLOW_INSECURE_HTTP=true`.
    """
    if urlparse(ES_HOST).scheme == "https":
        return
    if _es_host_es_loopback(ES_HOST) or ES_ALLOW_INSECURE_HTTP:
        return
    raise ESInsecureTransport(
        f"ES_HOST={ES_HOST} usa HTTP hacia un host remoto: las credenciales "
        f"viajarían en claro. Usá https:// (con ES_CA_CERT) o, si es un "
        f"laboratorio aislado, poné ES_ALLOW_INSECURE_HTTP=true.")


def _es_request(index: str, query: dict, timeout: int = 10) -> dict:
    """Única puerta hacia Elasticsearch: request, errores y TLS en un solo lugar.

    R-01: antes `es_search` y `es_aggregate` repetían este bloque con manejos de
    error distintos entre sí, lo que hacía que un mismo fallo se comportara de
    dos maneras según por dónde entrara.

    B-01: se captura `RequestException`, no solo `ConnectionError`. Un
    `ReadTimeout` (el caso común cuando ES está vivo pero saturado) NO hereda de
    `ConnectionError`, así que antes escapaba y rompía `prepare-for-ia.py` con un
    traceback en vez del mensaje de ayuda.
    """
    _verificar_transporte()
    url = f"{ES_HOST}/{index}/_search"
    try:
        r = requests.post(url, auth=_AUTH, headers=_HEADERS, json=query,
                          timeout=timeout, verify=ES_VERIFY_TLS)
        r.raise_for_status()
        return r.json()
    except requests.exceptions.HTTPError as e:
        if e.response is not None and e.response.status_code == 404:
            # Índice inexistente todavía: no es un error fatal, no hay datos aún.
            return {}
        codigo = e.response.status_code if e.response is not None else "?"
        raise ESUnavailable(f"HTTP {codigo} desde Elasticsearch: {e}") from e
    except requests.exceptions.ConnectionError as e:
        raise ESUnavailable(f"No se pudo conectar a Elasticsearch en {ES_HOST}") from e
    except requests.exceptions.Timeout as e:
        raise ESUnavailable(
            f"Elasticsearch no respondió en {timeout}s ({ES_HOST}): puede estar "
            f"saturado o iniciando.") from e
    except requests.exceptions.RequestException as e:
        raise ESUnavailable(f"Error hablando con Elasticsearch en {ES_HOST}: {e}") from e
    except ValueError as e:  # json() sobre una respuesta que no es JSON
        raise ESUnavailable(f"Respuesta no-JSON desde Elasticsearch: {e}") from e


def es_search(index: str, query: dict, timeout: int = 10) -> list[dict]:
    """Ejecuta un _search y devuelve la lista de hits (_source ya desempaquetado)."""
    return _es_request(index, query, timeout).get("hits", {}).get("hits", [])


def _time_range(window: str) -> dict:
    return {"range": {"@timestamp": {"gte": f"now-{window}", "lte": "now"}}}


def auth_failure_query(size: int, window: str = "24h") -> dict:
    """Logs de autenticación fallida dentro de una ventana temporal."""
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "message", "host.ip", "host.name",
                    "log.file.path", "tags", "fields", "source_ip", "user"],
        "query": {
            "bool": {
                "filter": [
                    _time_range(window),
                    # Restringido a las fuentes REALES de auth SSH: el contenedor de
                    # simulación, o (despliegue no containerizado) el módulo system/auth
                    # de Filebeat. El input `container` de Filebeat indexa el stdout de
                    # TODOS los contenedores sin discriminar — Kibana incluido — y una
                    # frase como "authentication failure" hacía falso positivo contra el
                    # propio NOMBRE de la regla A7 ("SSH Isolated Authentication Failure")
                    # cada vez que Kibana logueaba haberla ejecutado: un incidente fantasma,
                    # sin atacante ni regla real detrás.
                    {
                        "bool": {
                            "should": [
                                {"term": {"container.name.keyword": "ssh-target"}},
                                {"term": {"fields.source_type.keyword": "system_logs"}},
                            ],
                            "minimum_should_match": 1,
                        }
                    },
                ],
                "must": [{
                    "bool": {
                        "should": [
                            {"match_phrase": {"message": "Failed password"}},
                            {"match_phrase": {"message": "authentication failure"}},
                            {"match_phrase": {"message": "Invalid user"}},
                            {"term": {"tags.keyword": "authentication_failure"}},
                        ],
                        "minimum_should_match": 1,
                    }
                }],
                "must_not": [
                    {"match_phrase": {"log.file.path": "Xorg"}},
                    {"match_phrase": {"message": "AMDGPU"}},
                ],
            }
        },
    }


# Campo por el que se agrupan las alertas para que ninguna regla monopolice la
# muestra. Es `keyword` en el índice de alertas de Elastic Security.
ALERT_RULE_FIELD = "kibana.alert.rule.name"

# Qué SIGNIFICA el valor por el que agrupó una regla threshold.
#
# Una alerta threshold trae en `threshold_result.terms[0]` el campo Y el valor
# por los que agrupó. No es lo mismo agrupar por `source_ip` que por `host.ip`:
# el primero identifica a quien ataca, el segundo a quien recibe el ataque.
#
# Tratarlos igual es el mismo error que el hallazgo L-02, que confundía atacante
# con víctima en el camino de los logs. Acá se cierra el camino de las alertas.
ROL_POR_CAMPO_AGRUPADO = {
    "source_ip": "atacante",
    "host.ip":   "victima",
    "host.name": "victima",
    "user":      "usuario",
}


def rol_del_campo_agrupado(campo: object) -> str | None:
    """Devuelve 'atacante', 'victima', 'usuario' o None si no se reconoce.

    Acepta el campo con o sin el sufijo `.keyword` con el que aparece en las
    reglas (`source_ip.keyword`), porque es el mismo campo lógico.
    """
    if not isinstance(campo, str) or not campo:
        return None
    return ROL_POR_CAMPO_AGRUPADO.get(campo.removesuffix(".keyword"))


def alerts_query(size: int, window: str = "24h") -> dict:
    """Alertas de seguridad de la ventana, las más recientes primero.

    Se conserva para inspección ad-hoc (`get-logs.py`). El pipeline usa
    `alerts_query_por_regla`, que evita que una regla ruidosa tape a las demás.
    """
    return {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"filter": [_time_range(window)], "must": [{"match_all": {}}]}},
    }


def alerts_query_por_regla(por_regla: int = 3, max_reglas: int = 50,
                           window: str = "24h") -> dict:
    """Las N alertas más recientes DE CADA REGLA.

    **Por qué no alcanza con pedir las N más recientes a secas.** Una regla
    ruidosa desplaza a todas las demás: con 116 alertas de 8 reglas en la
    ventana, `size=10` devolvía 10 alertas de una sola regla — y entre las que
    quedaban afuera estaba `SSH Successful Login After Brute Force`, la crítica
    que significa que la fuerza bruta funcionó.

    El problema empeora cuanto mejor está configurado el SIEM: apareció al
    desplegar las 13 reglas del catálogo, donde antes había 4.

    Agrupar por regla garantiza que cada detección activa llegue al clasificador,
    sin importar cuántas veces haya disparado otra.
    """
    return {
        "size": 0,
        "query": {"bool": {"filter": [_time_range(window)], "must": [{"match_all": {}}]}},
        "aggs": {
            "por_regla": {
                "terms": {"field": ALERT_RULE_FIELD, "size": max_reglas},
                "aggs": {
                    "recientes": {
                        "top_hits": {
                            "size": por_regla,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                        }
                    }
                },
            }
        },
    }


def source_ip_aggregation(window: str = "24h") -> dict:
    """Agrega fallos de auth por IP origen — base del 'historial de la IP en 24h'.

    **`.keyword` no es opcional (D-12).** No hay plantilla de índice para
    `filebeat-*`, así que el mapeo es dinámico y `source_ip` queda como `text` con
    un subcampo `keyword`. Agregar sobre el `text` devuelve
    `Fielddata is disabled on [source_ip]` — un HTTP 400 que aborta toda la captura
    de Elasticsearch.

    El catálogo de reglas ya documentaba esta trampa y se corrigió en la tarea P3;
    esta agregación, que vive en el código y no en las reglas, quedó afuera. Se
    descubrió construyendo la demostración desde cero: con los índices recién
    creados el pipeline dejaba de capturar del SIEM y clasificaba solo desde
    `network_logs/`, sin un solo incidente de autenticación.
    """
    return {
        "size": 0,
        "query": {
            "bool": {
                "filter": [_time_range(window)],
                "must": [{"term": {"tags": "authentication_failure"}}],
            }
        },
        "aggs": {
            "by_source_ip": {
                "terms": {"field": "source_ip.keyword", "size": 10,
                          "order": {"_count": "desc"}}
            }
        },
    }


def es_aggregate(index: str, query: dict, agg_name: str, timeout: int = 10) -> list[dict]:
    """Devuelve los buckets de una agregación terms."""
    agregaciones = _es_request(index, query, timeout).get("aggregations", {})
    return agregaciones.get(agg_name, {}).get("buckets", [])


def es_search_por_grupo(index: str, query: dict, agg_name: str = "por_regla",
                        hits_name: str = "recientes", timeout: int = 10) -> list[dict]:
    """Aplana una agregación `terms` + `top_hits` a una lista de hits.

    Devuelve lo mismo que `es_search` —hits con `_source`— para que el resto del
    pipeline no tenga que distinguir de dónde vinieron. Los hits salen ordenados
    del más reciente al más antiguo entre todos los grupos.
    """
    agregaciones = _es_request(index, query, timeout).get("aggregations", {})
    hits: list[dict] = []
    for bucket in agregaciones.get(agg_name, {}).get("buckets", []):
        hits.extend(bucket.get(hits_name, {}).get("hits", {}).get("hits", []))

    hits.sort(key=lambda h: h.get("_source", {}).get("@timestamp") or "", reverse=True)
    return hits
