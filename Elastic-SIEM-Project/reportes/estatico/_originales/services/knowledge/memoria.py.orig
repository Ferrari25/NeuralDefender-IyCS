#!/usr/bin/env python3
"""Memoria del Agente 2: lo que el sistema aprende con el uso.

Un "Gem" de Gemini es un prompt fijo más unos archivos de conocimiento: no
aprende solo. Este módulo le da al Agente 2 lo que le falta para eso, con tres
fuentes, todas escritas por personas — nunca por un log:

  - **Documentos**: conocimiento de la organización que un analista carga desde
    el panel (inventario de red, políticas, escáneres internos autorizados...).
  - **Casos**: cada decisión de un analista (aprobar/descartar) se guarda como
    un caso resuelto, con el tipo de ataque, las IPs, la acción y la nota.
  - **Lecciones**: reglas cortas ("los port scans desde 10.0.5.20 son el Nessus
    interno") que el sistema PROPONE a partir de los casos, o que un analista
    escribe a mano. **Una lección solo se usa una vez aprobada por un analista.**

Por qué la aprobación manual no es opcional: el atacante controla parte de los
datos del incidente (el usuario que tipea, la IP de origen). Si el sistema
aprendiera solo, un atacante podría "entrenarlo" generando incidentes que un
analista descarta, hasta que su IP quedara marcada como ruido. Con aprobación,
el sistema sugiere qué aprender y el humano decide — el mismo principio que
rige las acciones de contención.

La propuesta automática de lecciones y la búsqueda de contexto son
determinísticas (reglas y puntajes, sin LLM): una lección tiene que poder
explicarse con los casos que la originaron.
"""

from __future__ import annotations

import hashlib
import re
import threading
import unicodedata
from pathlib import Path

from siem_lib import load_json, now_iso, write_json

DOCS_FILE = "data/documentos.json"
CASOS_FILE = "data/casos.json"
LECCIONES_FILE = "data/lecciones.json"

MAX_TITULO = 120
MAX_DOCUMENTO = 32 * 1024     # el panel acepta cuerpos de 64 KB; sobra margen
MAX_DOCUMENTOS = 50
MAX_LECCION = 400
MAX_NOTA = 500

# Cuántos casos de un mismo patrón (tipo de ataque + IP), en incidentes
# DISTINTOS y con el mismo desenlace, hacen falta para proponer una lección.
# Dos es poco para producción y justo para una demo: el umbral está a la vista.
CASOS_PARA_PROPONER = 2

TIPOS_LECCION = ("falso_positivo", "reincidente", "manual")
ESTADOS_LECCION = ("propuesta", "aprobada", "rechazada")
REVISIONES = {"aprobar": "aprobada", "rechazar": "rechazada"}

# Palabras que identifican cada tipo de ataque en un documento escrito por una
# persona. Son las que se buscan, además de las IPs/usuarios/hosts del incidente.
TERMINOS_POR_ATAQUE = {
    "ssh_brute_force": ("ssh", "fuerza", "bruta", "brute", "force", "contrasena", "password", "t1110"),
    "port_scan": ("escaneo", "escaner", "scan", "scanner", "puertos", "nmap", "nessus", "t1046"),
    "credential_harvesting": ("phishing", "credenciales", "login", "correo", "t1566"),
    "suspicious_auth": ("autenticacion", "login", "ssh"),
}

# Un solo escritor a la vez por archivo (gunicorn corre con varios hilos).
_lock = threading.Lock()


class ErrorDeMemoria(ValueError):
    """Un dato que la memoria no acepta. El mensaje se le muestra al analista."""


# ─── Persistencia ────────────────────────────────────────────────────────────

def _leer(ruta: str) -> list[dict]:
    if not Path(ruta).exists():
        return []
    datos = load_json(ruta)
    return datos if isinstance(datos, list) else []


def _id(prefijo: str, *partes: str) -> str:
    semilla = "|".join(partes)
    return f"{prefijo}-{hashlib.sha256(semilla.encode(), usedforsecurity=False).hexdigest()[:10]}"


def _texto(valor: object, campo: str, maximo: int, obligatorio: bool = True) -> str:
    if valor is None and not obligatorio:
        return ""
    if not isinstance(valor, str):
        raise ErrorDeMemoria(f"'{campo}' debe ser texto")
    limpio = valor.strip()
    if obligatorio and not limpio:
        raise ErrorDeMemoria(f"falta '{campo}'")
    if len(limpio) > maximo:
        raise ErrorDeMemoria(f"'{campo}' supera {maximo} caracteres ({len(limpio)})")
    return limpio


def _lista_de_textos(valor: object, campo: str) -> list[str]:
    if valor is None:
        return []
    if not isinstance(valor, list) or not all(isinstance(v, str) for v in valor):
        raise ErrorDeMemoria(f"'{campo}' debe ser una lista de textos")
    return [v.strip()[:100] for v in valor if v.strip()][:20]


# ─── Documentos ──────────────────────────────────────────────────────────────

def listar_documentos() -> list[dict]:
    """Metadatos de cada documento (sin el contenido completo)."""
    return [{k: d[k] for k in ("doc_id", "titulo", "subido_por", "ts", "caracteres")}
            for d in _leer(DOCS_FILE)]


def agregar_documento(titulo: object, contenido: object, subido_por: object) -> dict:
    titulo = _texto(titulo, "titulo", MAX_TITULO)
    contenido = _texto(contenido, "contenido", MAX_DOCUMENTO)
    subido_por = _texto(subido_por, "subido_por", 64)
    with _lock:
        docs = _leer(DOCS_FILE)
        if len(docs) >= MAX_DOCUMENTOS:
            raise ErrorDeMemoria(f"se alcanzó el máximo de {MAX_DOCUMENTOS} documentos")
        ts = now_iso()
        doc = {"doc_id": _id("DOC", titulo, ts), "titulo": titulo, "contenido": contenido,
               "subido_por": subido_por, "ts": ts, "caracteres": len(contenido)}
        docs.append(doc)
        write_json(DOCS_FILE, docs)
    return {k: v for k, v in doc.items() if k != "contenido"}


# ─── Casos (decisiones resueltas) ────────────────────────────────────────────

def agregar_caso(datos: dict) -> tuple[dict, list[dict]]:
    """Guarda un caso resuelto y devuelve `(caso, lecciones_nuevas_propuestas)`."""
    decision = datos.get("decision")
    if decision not in ("approved", "dismissed"):
        raise ErrorDeMemoria("decision inválida (approved|dismissed)")
    caso = {
        "incident_id": _texto(datos.get("incident_id"), "incident_id", 100),
        "action_id": _texto(datos.get("action_id"), "action_id", 100),
        "accion": _texto(datos.get("accion"), "accion", 300, obligatorio=False),
        "decision": decision,
        "note": _texto(datos.get("note"), "note", MAX_NOTA, obligatorio=False),
        "analyst": _texto(datos.get("analyst"), "analyst", 64),
        "attack_type": _texto(datos.get("attack_type"), "attack_type", 60),
        "severity": _texto(datos.get("severity"), "severity", 20, obligatorio=False),
        "source_ip": _texto(datos.get("source_ip"), "source_ip", 64, obligatorio=False),
        "attacker_ips": _lista_de_textos(datos.get("attacker_ips"), "attacker_ips"),
        "target_users": _lista_de_textos(datos.get("target_users"), "target_users"),
        "ts": now_iso(),
    }
    with _lock:
        casos = _leer(CASOS_FILE)
        casos.append(caso)
        write_json(CASOS_FILE, casos)
        nuevas = _proponer_lecciones(casos)
    return caso, nuevas


def _ips_de(registro: dict) -> set[str]:
    ips = {registro.get("source_ip")} | set(registro.get("attacker_ips") or [])
    return {ip for ip in ips if ip and ip != "desconocida"}


def _desenlace_por_incidente(casos: list[dict]) -> dict[str, dict]:
    """Un desenlace por incidente: replay de la última decisión por acción.

    Un incidente cuenta como "aprobado" si alguna de sus acciones quedó
    aprobada, y como "descartado" si TODAS las decididas quedaron descartadas.
    """
    ultima_por_accion: dict[str, dict] = {}
    for c in casos:
        ultima_por_accion[c["action_id"]] = c
    incidentes: dict[str, dict] = {}
    for c in ultima_por_accion.values():
        inc = incidentes.setdefault(c["incident_id"], {
            "attack_type": c["attack_type"], "ips": set(), "decisiones": set(), "notas": []})
        inc["ips"] |= _ips_de(c)
        inc["decisiones"].add(c["decision"])
        if c.get("note"):
            inc["notas"].append(c["note"])
    for inc in incidentes.values():
        inc["desenlace"] = "approved" if "approved" in inc["decisiones"] else "dismissed"
    return incidentes


def _proponer_lecciones(casos: list[dict]) -> list[dict]:
    """Propone lecciones cuando un patrón se repite con el mismo desenlace.

    Patrón = (tipo de ataque, IP). Si en `CASOS_PARA_PROPONER` incidentes
    distintos el analista decidió siempre lo mismo, se propone una lección.
    Nunca se re-propone un patrón que ya tiene lección, en ningún estado: una
    lección rechazada sigue rechazada.
    """
    patrones: dict[tuple[str, str], list[dict]] = {}
    for incidente_id, inc in _desenlace_por_incidente(casos).items():
        for ip in inc["ips"]:
            patrones.setdefault((inc["attack_type"], ip), []).append({"id": incidente_id, **inc})

    lecciones = _leer(LECCIONES_FILE)
    existentes = {(lec.get("tipo"), lec.get("attack_type"), lec.get("ip")) for lec in lecciones}
    nuevas = []
    for (attack_type, ip), incs in sorted(patrones.items()):
        desenlaces = {i["desenlace"] for i in incs}
        if len(incs) < CASOS_PARA_PROPONER or len(desenlaces) != 1:
            continue
        tipo = "falso_positivo" if desenlaces == {"dismissed"} else "reincidente"
        if (tipo, attack_type, ip) in existentes:
            continue
        notas = sorted({n for i in incs for n in i["notas"]})[:3]
        if tipo == "falso_positivo":
            texto = (f"Los incidentes de tipo {attack_type} desde {ip} fueron descartados por "
                     f"los analistas en {len(incs)} incidentes distintos: probable falso positivo.")
        else:
            texto = (f"La IP {ip} ya motivó acciones aprobadas en {len(incs)} incidentes de tipo "
                     f"{attack_type}: tratarla como atacante reincidente.")
        if notas:
            texto += " Notas de los analistas: " + " / ".join(notas)
        nuevas.append(_nueva_leccion(tipo, texto[:MAX_LECCION], attack_type, ip,
                                     propuesta_por="sistema",
                                     evidencia=sorted(i["id"] for i in incs)))
    if nuevas:
        write_json(LECCIONES_FILE, lecciones + nuevas)
    return nuevas


# ─── Lecciones ───────────────────────────────────────────────────────────────

def _nueva_leccion(tipo: str, texto: str, attack_type: str | None, ip: str | None,
                   propuesta_por: str, evidencia: list[str] | None = None) -> dict:
    ts = now_iso()
    return {
        "leccion_id": _id("LEC", tipo, str(attack_type), str(ip), texto, ts),
        "tipo": tipo, "texto": texto, "attack_type": attack_type, "ip": ip,
        "estado": "propuesta", "propuesta_por": propuesta_por, "propuesta_en": ts,
        "evidencia": evidencia or [], "revisada_por": None, "revisada_en": None,
    }


def listar_lecciones() -> list[dict]:
    return _leer(LECCIONES_FILE)


def proponer_leccion_manual(texto: object, attack_type: object, ip: object,
                            propuesta_por: object) -> dict:
    """Un analista le enseña algo al agente. Igual queda como PROPUESTA."""
    texto = _texto(texto, "texto", MAX_LECCION)
    attack_type = _texto(attack_type, "attack_type", 60, obligatorio=False) or None
    if attack_type and attack_type not in TERMINOS_POR_ATAQUE:
        raise ErrorDeMemoria(f"attack_type desconocido: {attack_type!r}")
    ip = _texto(ip, "ip", 64, obligatorio=False) or None
    propuesta_por = _texto(propuesta_por, "propuesta_por", 64)
    with _lock:
        lecciones = _leer(LECCIONES_FILE)
        leccion = _nueva_leccion("manual", texto, attack_type, ip, propuesta_por)
        lecciones.append(leccion)
        write_json(LECCIONES_FILE, lecciones)
    return leccion


def revisar_leccion(leccion_id: str, decision: object, revisor: object) -> dict:
    """Aprueba o rechaza una lección propuesta. Una lección revisada no se reabre."""
    if decision not in REVISIONES:
        raise ErrorDeMemoria("decision inválida (aprobar|rechazar)")
    revisor = _texto(revisor, "revisor", 64)
    with _lock:
        lecciones = _leer(LECCIONES_FILE)
        leccion = next((lec for lec in lecciones if lec.get("leccion_id") == leccion_id), None)
        if leccion is None:
            raise KeyError(leccion_id)
        if leccion["estado"] != "propuesta":
            raise ErrorDeMemoria(f"la lección ya fue {leccion['estado']}")
        leccion.update(estado=REVISIONES[decision], revisada_por=revisor, revisada_en=now_iso())
        write_json(LECCIONES_FILE, lecciones)
    return leccion


# ─── Contexto para un incidente ──────────────────────────────────────────────

def _normalizar(texto: str) -> str:
    sin_tildes = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return sin_tildes.lower()


_PALABRA = re.compile(r"[a-z0-9][a-z0-9._-]{2,}")


def _terminos(incidente: dict) -> dict[str, int]:
    """Términos a buscar en los documentos, con su peso.

    Un dato propio del incidente (IP, usuario, host, puerto) pesa más que una
    palabra genérica del tipo de ataque: que un documento mencione la IP exacta
    es mucho más relevante que que hable de "ssh" en general.
    """
    pesos: dict[str, int] = {}
    for t in TERMINOS_POR_ATAQUE.get(incidente.get("attack_type") or "", ()):
        pesos[t] = 1
    especificos = [*_ips_de(incidente), *(incidente.get("target_users") or []),
                   *(incidente.get("target_hosts") or [])]
    for t in especificos:
        if isinstance(t, str) and len(t) >= 3:
            pesos[_normalizar(t)] = 4
    return pesos


def _fragmentos_relevantes(incidente: dict, docs: list[dict], maximo: int = 3) -> list[dict]:
    terminos = _terminos(incidente)
    candidatos = []
    for doc in docs:
        for parrafo in re.split(r"\n\s*\n", doc.get("contenido") or ""):
            plano = _normalizar(parrafo)
            palabras = set(_PALABRA.findall(plano))
            puntaje = sum(peso for t, peso in terminos.items()
                          if t in palabras or (peso > 1 and t in plano))
            if puntaje >= 2:
                candidatos.append((puntaje, doc["titulo"], doc["doc_id"], " ".join(parrafo.split())))
    candidatos.sort(key=lambda c: -c[0])
    return [{"doc_id": d, "titulo": t, "fragmento": f[:600], "relevancia": p}
            for p, t, d, f in candidatos[:maximo]]


def _casos_similares(incidente: dict, casos: list[dict], maximo: int = 3) -> list[dict]:
    """Incidentes YA RESUELTOS parecidos a este (no el mismo incidente)."""
    ips = _ips_de(incidente)
    usuarios = set(incidente.get("target_users") or [])
    por_incidente: dict[str, dict] = {}
    for c in casos:
        if c["incident_id"] == incidente.get("incident_id"):
            continue
        puntaje = 0
        motivos = []
        if c["attack_type"] == incidente.get("attack_type"):
            puntaje += 3
            motivos.append("mismo tipo de ataque")
        compartidas = _ips_de(c) & ips
        if compartidas:
            puntaje += 4
            motivos.append(f"misma IP ({', '.join(sorted(compartidas))})")
        if usuarios & set(c.get("target_users") or []):
            puntaje += 1
            motivos.append("mismo usuario objetivo")
        if puntaje < 3:
            continue
        previo = por_incidente.get(c["incident_id"])
        # Por incidente queda la decisión más reciente, con su puntaje.
        if previo is None or c["ts"] >= previo["ts"]:
            por_incidente[c["incident_id"]] = {
                "incident_id": c["incident_id"], "attack_type": c["attack_type"],
                "decision": c["decision"], "accion": c.get("accion"), "note": c.get("note"),
                "analyst": c["analyst"], "ts": c["ts"], "similitud": puntaje,
                "motivo": ", ".join(motivos)}
    similares = sorted(por_incidente.values(), key=lambda s: (s["similitud"], s["ts"]), reverse=True)
    return similares[:maximo]


def _lecciones_aplicables(incidente: dict, lecciones: list[dict]) -> list[dict]:
    """Lecciones APROBADAS cuyo alcance cubre este incidente.

    Una lección sin tipo de ataque ni IP es general y aplica a todos.
    """
    ips = _ips_de(incidente)
    return [
        {k: lec[k] for k in ("leccion_id", "tipo", "texto", "attack_type", "ip", "revisada_por")}
        for lec in lecciones
        if lec.get("estado") == "aprobada"
        and (not lec.get("attack_type") or lec["attack_type"] == incidente.get("attack_type"))
        and (not lec.get("ip") or lec["ip"] in ips)
    ]


def contexto_para(incidentes: list[dict]) -> dict[str, dict]:
    """Para cada incidente: lecciones aprobadas, casos similares y fragmentos de documentos."""
    docs, casos, lecciones = _leer(DOCS_FILE), _leer(CASOS_FILE), _leer(LECCIONES_FILE)
    contexto = {}
    for inc in incidentes:
        if not isinstance(inc, dict) or not isinstance(inc.get("incident_id"), str):
            raise ErrorDeMemoria("cada incidente necesita un 'incident_id'")
        contexto[inc["incident_id"]] = {
            "lecciones": _lecciones_aplicables(inc, lecciones),
            "casos_similares": _casos_similares(inc, casos),
            "documentos": _fragmentos_relevantes(inc, docs),
        }
    return contexto
