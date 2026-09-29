#!/usr/bin/env python3
"""
Librería común del SIEM-IA.

Centraliza lo que antes estaba duplicado entre get-logs.py y prepare-for-ia.py:
conexión a Elasticsearch, queries con rango temporal, agregación por IP, y
utilidades de archivos (carga JSON, append-only JSONL). También expone helpers
de saneamiento usados antes de mandar datos de logs (no confiables) a un LLM.
"""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

load_dotenv()

# ─── Configuración (desde .env) ──────────────────────────────────────────────

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

# Permisos de los registros de auditoría: solo el dueño (A-02).
AUDIT_FILE_MODE = 0o600

# Eslabón raíz de la cadena de hashes (A-04): el `prev_hash` del primer registro.
GENESIS_HASH = "0" * 64

# Artefactos regenerables del pipeline: contienen datos de log, no auditoría.
DATA_FILE_MODE = 0o600


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_ts(valor: object) -> datetime | None:
    """Convierte un timestamp ISO-8601 a `datetime` con zona horaria (B-03).

    Elasticsearch emite `2026-09-16T10:00:00.000Z` y `now_iso()` emite
    `2026-09-16T10:00:00+00:00`: el MISMO instante con dos formatos. Comparados
    como texto, `Z` (0x5A) ordena después de `+` (0x2B), así que el orden
    lexicográfico no coincide con el cronológico y `first_seen`/`last_seen`
    quedaban mal cuando las dos fuentes se mezclaban.

    Devuelve `None` si el valor no es una fecha, para que el llamador decida.
    """
    if isinstance(valor, datetime):
        return valor if valor.tzinfo else valor.replace(tzinfo=timezone.utc)
    if not isinstance(valor, str) or not valor.strip():
        return None
    texto = valor.strip()
    if texto.endswith(("Z", "z")):
        texto = texto[:-1] + "+00:00"
    try:
        parseado = datetime.fromisoformat(texto)
    except ValueError:
        return None
    return parseado if parseado.tzinfo else parseado.replace(tzinfo=timezone.utc)


def ts_ordenable(valor: object) -> datetime:
    """Como `parse_ts`, pero devuelve el instante mínimo si no se puede parsear.

    Sirve para ordenar sin que un timestamp roto rompa el `sorted()`.
    """
    return parse_ts(valor) or datetime.min.replace(tzinfo=timezone.utc)


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


# ─── Saneamiento (datos de log = contenido NO confiable) ─────────────────────

def is_private_ip(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def sanitize_for_prompt(text: str | None, max_len: int = 300) -> str:
    """Neutraliza contenido de logs antes de incrustarlo en un prompt de LLM.

    El campo `message` de un log SSH lo controla el atacante (ej: el username que
    tipea). Aplastamos saltos de línea y recortamos para reducir la superficie de
    inyección de prompt. La defensa principal sigue siendo la system instruction
    y el esquema estructurado; esto es defensa en profundidad.
    """
    if not text:
        return ""
    flat = " ".join(str(text).split())
    if len(flat) > max_len:
        flat = flat[:max_len] + "…"
    return flat


# ─── Utilidades de archivos ──────────────────────────────────────────────────

def load_json(path: str | Path) -> Any:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"No se encontró '{p}'.")
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, data: Any) -> None:
    """Escribe un JSON con permisos restrictivos.

    `siem_clean.json` y `siem_incidents.json` no son auditoría (se regeneran en
    cada corrida), pero contienen IPs, nombres de usuario y fragmentos de log:
    no tienen por qué ser legibles para todos los usuarios de la máquina. Se usa
    `os.open` con modo explícito en vez del `open()` de siempre, que deja los
    permisos a merced del umask — es lo que señala la regla R8005 de
    pylint-secure-coding-standard.
    """
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, DATA_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _hash_registro(registro: dict) -> str:
    """SHA-256 del registro serializado de forma canónica.

    `sort_keys` es imprescindible: dos serializaciones del mismo registro con las
    claves en distinto orden darían hashes distintos y romperían la cadena.
    """
    canonico = json.dumps(registro, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
    return hashlib.sha256(canonico.encode("utf-8")).hexdigest()


def _ultimo_hash(path: Path) -> str:
    """Hash del último registro del archivo, o el eslabón raíz si está vacío."""
    if not path.exists() or path.stat().st_size == 0:
        return GENESIS_HASH
    ultima = ""
    with open(path, encoding="utf-8") as f:
        for linea in f:
            if linea.strip():
                ultima = linea.strip()
    if not ultima:
        return GENESIS_HASH
    try:
        return _hash_registro(json.loads(ultima))
    except json.JSONDecodeError:
        # Línea corrupta: se encadena sobre su texto crudo para que la
        # verificación falle de forma visible en vez de silenciar el daño.
        return hashlib.sha256(ultima.encode("utf-8")).hexdigest()


def append_jsonl(path: str | Path, record: dict, encadenar: bool = True) -> dict:
    """Append-only con bloqueo, fsync y encadenado por hash.

    Tres garantías que antes no existían (A-02 y A-04):

    1. **`flock(LOCK_EX)`** — Flask atiende en varios hilos, así que dos analistas
       decidiendo a la vez comparten proceso. Sin bloqueo, dos escrituras pueden
       entrelazarse y producir una línea corrupta en el registro de auditoría.
    2. **`flush()` + `fsync()`** — un corte de energía justo después de aprobar
       una acción no puede perder esa decisión: cuando la función retorna, el
       registro está en disco, no en el buffer del sistema operativo.
    3. **`prev_hash`** — cada registro lleva el SHA-256 del anterior. Editar o
       borrar una línea intermedia rompe la cadena y `audit_verify.py` lo
       detecta. Sin esto, "append-only" describía una intención; ahora es una
       propiedad verificable.

    El archivo se crea con permisos 0600: la auditoría no la lee cualquiera.

    Devuelve el registro tal como quedó escrito (con `prev_hash`).
    """
    p = Path(path)
    # O_APPEND hace que cada write vaya al final aunque otro proceso haya escrito
    # en el medio; el modo solo aplica si el archivo se crea en esta llamada.
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, AUDIT_FILE_MODE)
    try:
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                # El hash previo se lee CON el lock tomado: si se leyera antes,
                # dos escrituras concurrentes encadenarían sobre el mismo eslabón.
                completo = dict(record)
                if encadenar:
                    completo["prev_hash"] = _ultimo_hash(p)
                f.write(json.dumps(completo, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except Exception:
        raise
    return completo


def read_jsonl(path: str | Path, tolerante: bool = False) -> list[dict]:
    """Lee un NDJSON.

    Con `tolerante=True` se saltean las líneas malformadas en vez de abortar. Lo
    usa el dashboard: un solo byte corrupto en `decisions.jsonl` dejaba el panel
    entero inutilizable, porque `json.JSONDecodeError` subía hasta la vista. La
    integridad no se ignora, se comprueba aparte con `verificar_cadena()`.
    """
    p = Path(path)
    if not p.exists():
        return []
    out = []
    with open(p, encoding="utf-8") as f:
        for numero, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                if not tolerante:
                    raise
                out.append({"_linea_corrupta": numero, "_crudo": line[:200]})
    return out


def verificar_cadena(path: str | Path) -> dict:
    """Recorre el log y confirma que la cadena de hashes está intacta (A-04).

    Devuelve `{"estado", "chain_ok", "records", "first_broken", "reason"}`, donde
    `estado` distingue tres situaciones que NO significan lo mismo:

    - **`"ok"`** — la cadena se verificó entera.
    - **`"heredado"`** — el registro es anterior al encadenado (Fase 2): ningún
      registro tiene `prev_hash`. No se puede verificar, pero **no es evidencia
      de manipulación**. Confundir las dos cosas vuelve inútil la alerta: quien
      la vea seguido va a aprender a ignorarla.
    - **`"roto"`** — la cadena existe y no cierra: alguien editó, borró o insertó
      una línea después de que se escribiera.

    Un registro sin `prev_hash` DESPUÉS de otros que sí lo tienen sí es "roto":
    quitar el campo es una forma de manipulación, no un resto del pasado.
    """
    p = Path(path)
    if not p.exists():
        return {"estado": "ok", "chain_ok": True, "records": 0,
                "first_broken": None, "reason": "el registro todavía no existe"}

    # Hash del registro anterior, se haya escrito encadenado o no. Es lo que
    # `append_jsonl` usa como `prev_hash` del siguiente, así que sirve igual para
    # verificar el empalme entre el tramo heredado y el encadenado.
    hash_anterior = GENESIS_HASH
    total = 0
    encadenados = 0

    with open(p, encoding="utf-8") as f:
        for numero, linea in enumerate(f, 1):
            linea = linea.strip()
            if not linea:
                continue
            total += 1
            try:
                registro = json.loads(linea)
            except json.JSONDecodeError:
                return {"estado": "roto", "chain_ok": False, "records": total,
                        "first_broken": numero, "reason": "línea malformada"}

            if "prev_hash" not in registro:
                if encadenados > 0:
                    return {"estado": "roto", "chain_ok": False, "records": total,
                            "first_broken": numero,
                            "reason": "a este registro le falta prev_hash, pero los "
                                      "anteriores lo tenían: el campo fue eliminado"}
                # Tramo heredado: no se puede verificar, pero se sigue calculando
                # el hash para poder comprobar el empalme con el tramo encadenado.
                hash_anterior = _hash_registro(registro)
                continue

            if registro["prev_hash"] != hash_anterior:
                return {"estado": "roto", "chain_ok": False, "records": total,
                        "first_broken": numero,
                        "reason": "prev_hash no coincide: el registro anterior "
                                  "fue modificado o eliminado"}
            hash_anterior = _hash_registro(registro)
            encadenados += 1

    if encadenados == 0 and total > 0:
        return {"estado": "heredado", "chain_ok": False, "records": total,
                "first_broken": None,
                "reason": f"{total} registro(s) anteriores al encadenado por hash "
                          f"(Fase 2); no se pueden verificar, pero no hay indicio "
                          f"de manipulación"}

    resultado = {"estado": "ok", "chain_ok": True, "records": total,
                 "first_broken": None, "reason": None}
    if encadenados < total:
        resultado["reason"] = (f"{total - encadenados} registro(s) heredados al "
                               f"inicio; los {encadenados} siguientes verifican bien")
    return resultado


def read_network_logs(dir_path: str | Path = "network_logs",
                      window_hours: int | None = 24) -> list[dict]:
    """Lee los eventos NDJSON de network_logs/*.json dentro de una ventana temporal.

    Es el mismo directorio que Filebeat envía a Elasticsearch (input
    network-traffic). Leerlo localmente permite que el clasificador detecte
    ataques de red/web sin depender del stack levantado (modo demo offline).
    Tolera líneas malformadas para no romper la cadena por un log sucio.

    B-05: antes se leía **todo** el directorio sin filtrar. Como cada corrida de
    la simulación deja un archivo nuevo (con timestamp en el nombre, para no
    confundir el offset de Filebeat), los eventos viejos seguían sumando para
    siempre: dos corridas del mismo port scan producían un incidente de 52
    eventos en vez de 26, inflando la severidad con datos ya procesados. Ahora
    se aplica la MISMA ventana de 24 h que usan las consultas a Elasticsearch.

    `window_hours=None` desactiva el filtro (útil para inspección forense).
    """
    events: list[dict] = []
    d = Path(dir_path)
    if not d.exists():
        return events

    corte = None
    if window_hours is not None:
        corte = datetime.now(timezone.utc) - timedelta(hours=window_hours)

    for f in sorted(d.glob("*.json")):
        with open(f, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    evento = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if corte is not None:
                    ts = parse_ts(evento.get("@timestamp"))
                    # Un evento sin timestamp legible se conserva: descartarlo
                    # silenciosamente sería peor que analizarlo de más.
                    if ts is not None and ts < corte:
                        continue
                events.append(evento)
    return events
