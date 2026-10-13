#!/usr/bin/env python3
"""
Librería común del SIEM-IA (núcleo compartido entre microservicios).

Solo contiene lo que de verdad usan varios servicios: utilidades de tiempo,
saneamiento de datos de log (contenido NO confiable), lectura/escritura de JSON
con permisos restrictivos y la lectura de `network_logs/`.

Lo que antes también vivía acá se mudó al servicio que es su único dueño:
  - acceso a Elasticsearch       → services/collector/es_client.py
  - cadena de hashes / auditoría → services/audit/cadena.py
Así, por ejemplo, las credenciales de Elasticsearch solo existen en el
contenedor del collector, y solo el servicio de auditoría escribe el registro.
"""

from __future__ import annotations

import ipaddress
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

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
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, DATA_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


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
