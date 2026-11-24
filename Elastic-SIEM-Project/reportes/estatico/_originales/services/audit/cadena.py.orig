#!/usr/bin/env python3
"""
Registro append-only encadenado por hash (hallazgos A-02 y A-04).

Antes vivía en `siem_lib.py` y lo usaban el panel (decisiones) y el Agente 2
(historial de corridas), cada uno escribiendo el archivo por su cuenta. Ahora
el servicio de auditoría es el ÚNICO escritor: los demás le mandan registros
por HTTP. Un solo proceso dueño del archivo es más fácil de auditar que dos
procesos disciplinados compartiéndolo.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path

# Permisos de los registros de auditoría: solo el dueño (A-02).
AUDIT_FILE_MODE = 0o600

# Eslabón raíz de la cadena de hashes (A-04): el `prev_hash` del primer registro.
GENESIS_HASH = "0" * 64


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
    p.parent.mkdir(parents=True, exist_ok=True)
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
