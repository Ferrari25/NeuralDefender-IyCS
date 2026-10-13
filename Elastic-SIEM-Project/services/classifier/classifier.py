#!/usr/bin/env python3
"""
Agente 1 — Clasificador determinístico (sin LLM).

Construye incidentes a partir de dos fuentes y aplica reglas fijas (umbrales,
técnica MITRE) para decidir tipo de ataque, severidad y probabilidad de falso
positivo. "O cumple el patrón o no": etapa rápida, barata y auditable, ANTES de
gastar el LLM.

Fuentes:
  - siem_clean.json        → alertas + logs de auth fallida  (ataques SSH/auth)
  - network_logs/*.json    → eventos de red/web (NDJSON)      (port scan, phishing)
    (es el mismo directorio que Filebeat envía a Elasticsearch; leerlo localmente
     permite detectar sin el stack levantado, en modo demo offline.)

Tipos de ataque soportados: ssh_brute_force, port_scan, credential_harvesting
(phishing), suspicious_auth (sub-umbral), generic.

Cada incidente trae un playbook de acciones con COMANDOS FIJOS (de acá, no del
LLM) para que el operador nunca reciba un comando alucinado o inyectado vía logs.

Salida: `siem_incidents.json` (analysis = null; lo completa el Agente 2).
"""

from __future__ import annotations

import hashlib
import re
import shlex
from dataclasses import asdict, dataclass, field

from siem_lib import (
    load_json,
    now_iso,
    read_network_logs,
    sanitize_for_prompt,
    ts_ordenable,
    write_json,
)
from siem_validators import (
    IP_DESCONOCIDA,
    resolver_ip_atacante,
    safe_token,
    valid_ip,
    valid_username,
)

SIEM_FILE      = "data/siem_clean.json"
INCIDENTS_FILE = "data/siem_incidents.json"

# Umbrales de detección (dentro de la ventana analizada).
BRUTE_FORCE_THRESHOLD   = 20      # fallos de auth → fuerza bruta
CRITICAL_FAILURE_COUNT  = 5000    # por encima → severidad crítica
PORT_SCAN_DISTINCT_PORTS = 10     # puertos distintos sondeados → port scan

# Técnicas MITRE que detect_auth_incidents() acepta como "esto es una alerta de autenticación".
# Sin esta lista, cualquier alerta de Kibana (port scan, phishing) se procesaría acá también.
_AUTH_MITRE_TECHNIQUES = {"T1110"}
# Mismo criterio para port scan (reglas B1-B4) y phishing (reglas C1-C3): cada
# detector solo mira las alertas de SU técnica, no las 14 mezcladas.
_PORT_SCAN_MITRE_TECHNIQUES = {"T1046"}
_PHISHING_MITRE_TECHNIQUES  = {"T1566"}

# Orden de severidad del SIEM, para quedarnos con la alerta MÁS GRAVE cuando varias
# reglas de Kibana disparan sobre la misma IP (ver `detect_auth_incidents`).
_RANGO_SEVERIDAD_SIEM = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Solo para la etiqueta que se imprime en consola (`main()`): el valor interno
# de `severity` queda en español (lo usan las comparaciones y los tests), pero
# el panel siempre pinta la severidad en inglés (`SEV_DETERMINISTICA` en
# app.js, vía `severidad_ajustada` de siem_agent.py) — sin este mapeo la
# consola mostraría "[ALTA]" al lado de un badge "HIGH" para el mismo incidente.
_SEV_LABEL_EN = {"critica": "CRITICAL", "alta": "HIGH", "media": "MEDIUM", "baja": "LOW"}

_FROM_IP_RE = re.compile(r"from (\d{1,3}(?:\.\d{1,3}){3})")
_USER_RE    = re.compile(r"for (?:invalid user )?(\w+)")


def _total_eventos(inc: dict) -> int:
    """Cuántos eventos representa un incidente de autenticación.

    Se toma el MÁXIMO entre las líneas de log observadas y el conteo que reporta
    la alerta del SIEM, no la suma: describen el mismo ataque desde dos ángulos.
    `prepare-for-ia.py` trae una muestra acotada de logs (size=20) mientras que
    la regla threshold cuenta todo lo que vio Elasticsearch, así que sumarlos
    contaría dos veces los mismos intentos e inflaría la severidad.
    """
    return max(inc.get("log_event_count", 0), inc.get("alert_event_count", 0))


@dataclass
class Incident:
    """Forma canónica de un incidente (R-02).

    Las tres funciones `detect_*` construían a mano el mismo diccionario de 18
    claves. Además de repetir, permitía que una detección olvidara un campo: de
    hecho pasaba — `detect_port_scans` y `detect_phishing` no emitían
    `victim_hosts`, `log_event_count` ni `alert_event_count`, así que el
    dashboard recibía incidentes con formas distintas según de dónde venían.

    Los campos propios de un tipo de ataque (`scanned_ports`, `phishing_urls`,
    `target_hosts`) van en `extras`, que se aplana al serializar: no tiene
    sentido que un incidente de phishing lleve una lista vacía de puertos.
    """

    incident_id: str
    source_ip: str
    classification: dict
    recommended_actions: list[dict]
    first_seen: str
    last_seen: str
    event_count: int
    attacker_ips: list[str] = field(default_factory=list)
    victim_hosts: list[str] = field(default_factory=list)
    target_users: list[str] = field(default_factory=list)
    # De dónde salió la detección. `"elastic"` solo cuando el incidente se construyó
    # a partir de una alerta REAL de Elasticsearch —y entonces `rule_name`,
    # `severity_siem` y `risk_score` son los que trajo esa alerta—. `"clasificador"`
    # cuando lo detectó el Agente 1 por su cuenta, desde los logs.
    #
    # D-11: antes, `detect_port_scans` y `detect_phishing` fijaban a mano
    # `rule_name="Network port scan detection"` y `severity_siem="high"`. Ninguno de
    # esos nombres existe en Kibana: el catálogo llama a esas reglas «Port Scan –
    # Many Distinct Ports» y «Credential Submission to Suspicious Login». El panel
    # mostraba una procedencia del SIEM que no había ocurrido, y esos dos detectores
    # ni siquiera consultan Elasticsearch: leen `network_logs/` directamente.
    detection_source: str = "clasificador"
    rule_name: str | None = None
    severity_siem: str | None = None
    risk_score: int | None = None
    log_event_count: int = 0
    alert_event_count: int = 0
    mitre: dict = field(default_factory=dict)
    sample_messages: list[str] = field(default_factory=list)
    evidence: list[dict] = field(default_factory=list)
    extras: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serializa al contrato que consumen el Agente 2 y el dashboard.

        `analysis` arranca en None siempre: lo completa el Agente 2. Que esté
        acá y no en cada detector es justamente el punto del refactor.
        """
        salida = asdict(self)
        salida.pop("extras")
        salida["analysis"] = None
        salida.update(self.extras)
        return salida


def _hash_corto(texto: str, n: int = 8) -> str:
    """Sufijo corto y estable para un identificador legible.

    `usedforsecurity=False` no cambia el resultado: le dice al intérprete (y a
    bandit, que lo marcaba como B324) que este hash desambigua identificadores,
    no protege nada. Que sea SHA-256 y no SHA-1 no aporta seguridad acá, pero
    evita tener que explicar la excepción cada vez que alguien corre el SAST.
    """
    return hashlib.sha256(texto.encode(), usedforsecurity=False).hexdigest()[:n]


def _incident_id(prefix: str, ip: str, first_seen: str) -> str:
    return f"INC-{prefix}-{ip}-{_hash_corto(f'{prefix}|{ip}|{first_seen}')}"


# ─── Playbooks (acciones con comandos fijos) ─────────────────────────────────
#
# Los comandos salen de plantillas literales de este módulo, nunca del LLM. Y
# desde el hallazgo S-01, los valores que se interpolan (IP, usuario) pasan antes
# por `siem_validators`: si no validan, la acción NO se ofrece.
#
# Que el sistema no ejecute nada (ver tests/test_no_autonomy.py) no alcanza: el
# analista copia el comando y lo pega en una terminal con sudo. Un comando
# sugerido es, en la práctica, código que se va a ejecutar en manos de alguien.


def _cmd(plantilla: str, **partes: str) -> str:
    """Arma un comando incrustando solo valores ya validados y entrecomillados.

    `shlex.quote` es defensa en profundidad: los validadores ya garantizan que
    no haya metacaracteres, así que en la práctica no agrega comillas. Si algún
    día un validador se relaja, esto evita que el valor cambie la estructura del
    comando. Las tuberías y redirecciones que aparezcan vienen de la PLANTILLA,
    que es literal y está en este archivo; nunca de los datos.
    """
    seguras = {}
    for clave, valor in partes.items():
        if not safe_token(valor):
            raise ValueError(
                f"valor no apto para un comando en '{clave}': {valor!r} "
                f"(esto indica un validador incompleto, no un dato raro)")
        seguras[clave] = shlex.quote(valor)
    return plantilla.format(**seguras)


def _accion(orden: int, accion: str, responsable: str, plazo: str, impacto: str,
            comando: str | None = None, argv: list[str] | None = None,
            explicacion: str | None = None, resultado_simulado: str | None = None) -> dict:
    """Construye una acción del playbook con su forma canónica.

    `resultado_simulado` es una VISTA PREVIA de texto, escrita a mano acá,
    igual que `explicacion` — nunca el resultado de correr el comando de
    verdad. El sistema no ejecuta nada (tests/test_no_autonomy.py lo
    certifica); esto existe para que el analista entienda el impacto antes de
    decidir, no para simular que algo ya pasó. El panel lo rotula sin
    ambigüedad como simulado — ver `renderResultadoSimulado` en app.js.
    """
    return {
        "orden": orden, "accion": accion,
        "comando_sugerido": comando,
        # Forma en lista del mismo comando, para que nada tenga que volver a
        # parsear el string. Es `None` cuando el comando incluye una tubería.
        "comando_argv": argv,
        "comando_explicacion": explicacion,
        "resultado_simulado": resultado_simulado,
        "responsable": responsable, "plazo": plazo, "impacto": impacto,
    }


def _playbook(attack_type: str, ip: str | None, user: str | None, *,
              magnitud_critica: bool = False) -> list[dict]:
    """Devuelve las acciones sugeridas, OMITIENDO las que no se pueden resolver.

    `ip` y `user` se revalidan acá aunque el llamador ya lo haya hecho: es el
    único punto por el que pasan todos los comandos, y una sola puerta bien
    cerrada es más fácil de auditar que cinco llamadores disciplinados.

    Omitir una acción es la respuesta correcta cuando falta el dato: antes se
    emitía `sudo ufw deny from <IP_ATACANTE>`, un comando que el analista no
    puede ejecutar y que además enseña a ignorar lo que dice el panel (L-03).

    `magnitud_critica` es el único hecho de ESTE incidente que hoy influye en
    la prioridad de las acciones (lo pasa `detect_auth_incidents` cuando el
    volumen ya cruzó `CRITICAL_FAILURE_COUNT`, el mismo umbral que decide
    `severity="critica"` en `_classification`): con un volumen así, la
    mitigación estructural (fail2ban) deja de ser algo para las próximas 48h
    y pasa a ser tan urgente como bloquear la IP. No se usa para reordenar
    ACCIONES DE OTROS TIPOS de ataque ni para inventar una acción nueva — solo
    ajusta plazo/impacto de una que ya existía, con un hecho que el
    clasificador ya tenía calculado.
    """
    ip = valid_ip(ip)
    usr = valid_username(user)

    acciones: list[dict] = []

    if attack_type == "ssh_brute_force":
        if ip:
            acciones.append(_accion(
                1, "Bloquear la IP atacante en el firewall perimetral", "SOC", "inmediata", "alto",
                comando=_cmd("sudo ufw deny from {ip}", ip=ip),
                argv=["sudo", "ufw", "deny", "from", ip],
                explicacion=(
                    "Agrega una regla al firewall (UFW, sobre iptables) que descarta todo el "
                    "tráfico entrante desde esa IP puntual. No afecta a ningún otro origen ni "
                    "servicio; es reversible con 'ufw delete deny from <ip>'."),
                resultado_simulado=(
                    f"Regla añadida a UFW:\n"
                    f"  [ 3] Anywhere                   DENY IN    {ip}\n"
                    f"Desde ahora, todo paquete entrante con origen {ip} se descarta "
                    f"silenciosamente — el atacante ve la conexión como caída, no rechazada.")))
            acciones.append(_accion(
                2, "Verificar si hubo algún login EXITOSO desde la IP atacante",
                "sysadmin", "inmediata", "alto",
                comando=_cmd("grep 'Accepted password' /var/log/auth.log | grep {ip}", ip=ip),
                explicacion=(
                    "Búsqueda de solo lectura sobre el log de autenticación del host: filtra las "
                    "líneas de login aceptado y las cruza con la IP atacante. Si aparece algo, la "
                    "fuerza bruta encontró la contraseña y hay que tratarlo como una cuenta "
                    "comprometida, no solo como un intento fallido."),
                resultado_simulado=(
                    "Depende del log real del host — dos resultados posibles:\n"
                    f"  · Sin coincidencias → ningún login exitoso desde {ip}, la fuerza bruta\n"
                    "    no llegó a acertar una contraseña.\n"
                    f"  · Con coincidencias (ej. 'Accepted password for testuser from {ip}')\n"
                    "    → tratar la cuenta como comprometida de inmediato, no como sospecha.")))
        if usr:
            acciones.append(_accion(
                3, f"Forzar rotación de credenciales del usuario objetivo ({usr})",
                "sysadmin", "24h", "medio",
                comando=_cmd("sudo passwd {usr}", usr=usr),
                argv=["sudo", "passwd", usr],
                explicacion=(
                    "Inicia el cambio de contraseña del usuario atacado de forma interactiva. "
                    "Invalida la contraseña anterior — importante sobre todo si el paso anterior "
                    "mostró un login exitoso, porque esa contraseña ya quedó expuesta."),
                resultado_simulado=(
                    f"Changing password for user {usr}.\n"
                    "New password: \n"
                    "Retype new password: \n"
                    "passwd: password updated successfully\n"
                    f"La contraseña anterior de {usr} queda inválida de inmediato — cualquier "
                    "sesión que dependiera de ella hay que volver a abrirla.")))
        # Con volumen crítico, esperar 48h a la mitigación estructural deja la
        # misma ventana abierta que ya se cruzó con miles de intentos —
        # `magnitud_critica` la sube a la misma urgencia que bloquear la IP.
        fail2ban_plazo   = "inmediata" if magnitud_critica else "48h"
        fail2ban_impacto = "alto" if magnitud_critica else "medio"
        fail2ban_titulo  = (
            "Habilitar rate-limiting / fail2ban en el servicio SSH"
            + (" (prioridad elevada: volumen crítico)" if magnitud_critica else ""))
        acciones.append(_accion(
            4, fail2ban_titulo, "sysadmin", fail2ban_plazo, fail2ban_impacto,
            comando="sudo apt-get install -y fail2ban && sudo systemctl enable --now fail2ban",
            explicacion=(
                "Instala fail2ban (monitorea los logs de auth y banea automáticamente IPs con "
                "demasiados fallos) y lo deja corriendo de forma permanente. Es la mitigación "
                "estructural: evita que haga falta bloquear IPs a mano cada vez que se repita "
                "este mismo patrón de ataque."
                + (" Con este volumen de intentos, no conviene dejarla para las próximas 48h: "
                   "el mismo patrón puede repetirse desde otra IP antes de que se instale."
                   if magnitud_critica else "")),
            resultado_simulado=(
                "Setting up fail2ban (0.11.2-6) ...\n"
                "Created symlink /etc/systemd/system/multi-user.target.wants/fail2ban.service\n"
                "  → /lib/systemd/system/fail2ban.service.\n"
                "● fail2ban.service - Fail2Ban Service\n"
                "     Active: active (running)\n"
                "A partir de ahora, cualquier IP con demasiados fallos de SSH se banea sola, "
                "sin depender de que un analista lo haga a mano cada vez.")))

    elif attack_type == "port_scan":
        if ip:
            acciones.append(_accion(
                1, "Bloquear la IP que realiza el escaneo en el firewall", "SOC", "inmediata", "alto",
                comando=_cmd("sudo ufw deny from {ip}", ip=ip),
                argv=["sudo", "ufw", "deny", "from", ip],
                explicacion=(
                    "Igual que en fuerza bruta: agrega una regla de firewall que descarta todo el "
                    "tráfico de esa IP puntual, cortando el reconocimiento en curso."),
                resultado_simulado=(
                    f"Regla añadida a UFW:\n"
                    f"  [ 3] Anywhere                   DENY IN    {ip}\n"
                    "El escaneo en curso deja de recibir respuesta de ningún puerto — desde la "
                    "perspectiva del atacante, el host entero pasa a verse caído.")))
        acciones.append(_accion(
            2, "Revisar qué servicios/puertos quedaron expuestos en el host objetivo",
            "sysadmin", "24h", "medio",
            comando="sudo ss -tulnp", argv=["sudo", "ss", "-tulnp"],
            explicacion=(
                "Lista los puertos TCP/UDP (-t/-u) en escucha (-l) en este host, con el "
                "proceso dueño de cada uno (-p) y sin resolver nombres (-n, más rápido). Es de "
                "solo lectura: sirve para ver exactamente qué encontró el atacante al escanear, "
                "antes de decidir qué cerrar."),
            resultado_simulado=(
                "Netid  State   Local Address:Port   Process\n"
                "tcp    LISTEN  0.0.0.0:22           \"sshd\"\n"
                "tcp    LISTEN  0.0.0.0:5601         \"node\" (kibana)\n"
                "tcp    LISTEN  0.0.0.0:9200         \"java\" (elasticsearch)\n"
                "(salida real: depende de qué haya expuesto el host que se está revisando)")))
        acciones.append(_accion(
            3, "Cerrar puertos innecesarios y segmentar el host afectado",
            "sysadmin", "24h", "medio"))
        acciones.append(_accion(
            4, "Desplegar IDS de red (Suricata) para visibilidad de futuros escaneos",
            "SOC", "48h", "bajo"))

    elif attack_type == "credential_harvesting":
        if ip:
            acciones.append(_accion(
                1, "Dar de baja / bloquear el servidor de phishing (página falsa)",
                "SOC", "inmediata", "alto",
                comando=_cmd("sudo ufw deny from {ip}", ip=ip),
                argv=["sudo", "ufw", "deny", "from", ip],
                explicacion=(
                    "Bloquea en el firewall la IP que aloja la página de phishing, cortando el "
                    "acceso desde esta red hacia ese servidor — no da de baja la página en sí "
                    "(está fuera de nuestro control), pero corta la exposición local."),
                resultado_simulado=(
                    f"Regla añadida a UFW:\n"
                    f"  [ 3] Anywhere                   DENY OUT   {ip}\n"
                    "Ningún equipo de esta red vuelve a poder llegar a esa IP — pero la página "
                    "falsa sigue en línea para el resto de internet, fuera de nuestro control.")))
        if usr:
            acciones.append(_accion(
                2, f"Forzar reset de credenciales del usuario que envió datos ({usr})",
                "sysadmin", "inmediata", "alto",
                comando=_cmd("sudo passwd {usr}", usr=usr),
                argv=["sudo", "passwd", usr],
                explicacion=(
                    "Cambia la contraseña del usuario que envió sus credenciales a la página falsa. "
                    "Es la acción más urgente del incidente: esa contraseña ya está en manos del "
                    "atacante, tratarla como comprometida de inmediato, no como sospecha."),
                resultado_simulado=(
                    f"Changing password for user {usr}.\n"
                    "New password: \n"
                    "Retype new password: \n"
                    "passwd: password updated successfully\n"
                    f"La contraseña que {usr} envió a la página falsa deja de servirle al "
                    "atacante para entrar con ella.")))
        acciones.append(_accion(
            3, "Alertar a los usuarios afectados y reforzar concientización",
            "SOC", "inmediata", "medio"))
        acciones.append(_accion(
            4, "Agregar el indicador (IP/dominio) a la blocklist / threat intel",
            "SOC", "24h", "medio"))

    # Siempre queda al menos una acción: si no se pudo resolver ningún dato, la
    # respuesta honesta es escalar a una persona, no inventar un comando.
    if not acciones:
        return [_accion(1, "Escalar a analista L2 para revisión manual del evento",
                        "SOC", "alta", "medio")]

    for nuevo_orden, accion in enumerate(acciones, 1):
        accion["orden"] = nuevo_orden
    return acciones


def _classification(attack_type: str, magnitude: int, detail: str,
                     factors: list[str] | None = None) -> dict:
    table = {
        "ssh_brute_force": {
            "severity": "critica" if magnitude >= CRITICAL_FAILURE_COUNT else "alta",
            "confidence": "alta", "fp": "baja", "mitre": "T1110",
        },
        "port_scan": {
            "severity": "alta", "confidence": "alta", "fp": "baja", "mitre": "T1046",
        },
        "credential_harvesting": {
            "severity": "alta", "confidence": "media", "fp": "media", "mitre": "T1566",
        },
        "suspicious_auth": {
            "severity": "media", "confidence": "media", "fp": "media", "mitre": None,
        },
    }
    t = table.get(attack_type, table["suspicious_auth"])
    return {
        "attack_type": attack_type,
        "confidence": t["confidence"],
        "severity": t["severity"],
        "false_positive_likelihood": t["fp"],
        "rationale": detail,
        "mitre_technique": t["mitre"],
        # Explicabilidad: la lista concreta de señales que llevaron a esta severidad/confianza,
        # para que el analista (y el Agente 2) vean el "por qué", no solo el resultado.
        "factores": factors or [],
    }


def _finalize(incident_id: str, actions: list[dict]) -> list[dict]:
    """Asigna identidad y estado inicial a cada acción del playbook.

    A-03: el `action_id` se deriva del CONTENIDO de la acción (qué hace y qué
    comando propone), no de su posición en la lista. Antes era `-a1`, `-a2`…:
    si un playbook cambiaba de orden, o si una acción se omitía por falta de
    datos (algo que ahora pasa, desde S-01), las decisiones ya registradas en
    `decisions.jsonl` pasaban a apuntar a OTRA acción. Y ese registro es
    inmutable: no se puede corregir después.

    El `orden` sigue existiendo para mostrar, pero ya no define identidad.
    """
    vistos: dict[str, int] = {}
    for act in actions:
        semilla = f"{act['accion']}|{act.get('comando_sugerido') or ''}"
        corto = _hash_corto(semilla, 6)
        # Dos acciones idénticas en un mismo incidente no deberían existir, pero
        # si las hubiera no pueden compartir action_id.
        vistos[corto] = vistos.get(corto, 0) + 1
        sufijo = corto if vistos[corto] == 1 else f"{corto}-{vistos[corto]}"
        act["action_id"] = f"{incident_id}-{sufijo}"
        act["status"] = "pending"
    return actions


# ─── Detección: SSH / auth ───────────────────────────────────────────────────

def detect_auth_incidents(siem_data: dict) -> list[dict]:
    """Agrupa alertas y logs de autenticación en incidentes, por IP ATACANTE.

    Corrige dos hallazgos que se sostenían entre sí:

    **L-02 — identidad.** Antes, las alertas se agrupaban por `source_ip` (el
    atacante) y los logs por `host_ip` (la víctima), así que el mismo ataque
    172.18.0.3 → 172.18.0.7 producía DOS incidentes con identidades
    incompatibles: uno con la IP del atacante y sin usuarios, otro con la IP de
    la víctima y el atacante escondido en `attacker_ips`. Ahora la clave del
    bucket es siempre el atacante, que se extrae del `message` ANTES de decidir
    a qué incidente pertenece la línea. El host atacado pasa a `victim_hosts`.

    **L-01 — conteo.** Antes: `if not inc["event_count"]: inc["event_count"] += 1`,
    que incrementaba una sola vez y después nunca más, porque el valor ya era
    truthy. El contador quedaba clavado en 1 y, con el umbral en 20, ningún
    incidente construido solo desde logs podía alcanzarlo jamás: sin una alerta
    previa de Kibana, un ataque de 10 000 intentos se reportaba como "media,
    requiere revisión manual". Ahora se cuenta cada línea.
    """
    alerts = siem_data.get("alerts", [])
    logs   = siem_data.get("auth_failure_logs", [])
    incidents: dict[str, dict] = {}

    def ensure(attacker_ip: str, ts: str) -> dict:
        if attacker_ip not in incidents:
            incidents[attacker_ip] = {
                "attacker_ip": attacker_ip, "first_seen": ts, "last_seen": ts,
                "rule_name": None, "severity_siem": None, "risk_score": None,
                # Dos contadores separados: las alertas traen el conteo propio del
                # SIEM sobre los mismos eventos que ya están en los logs. Sumarlos
                # contaría dos veces el mismo ataque (ver `_total_eventos`).
                "log_event_count": 0, "alert_event_count": 0,
                "mitre": {}, "attacker_ips": set(), "victim_hosts": set(),
                "target_users": set(), "sample_messages": [], "evidence": [],
            }
        inc = incidents[attacker_ip]
        # B-03: comparación cronológica, no lexicográfica. Los logs vienen de ES
        # con sufijo `Z` y los timestamps generados acá con `+00:00`; como texto,
        # el mismo instante parecía distinto (y posterior).
        momento = ts_ordenable(ts)
        if ts and momento < ts_ordenable(inc["first_seen"]):
            inc["first_seen"] = ts
        if ts and momento > ts_ordenable(inc["last_seen"]):
            inc["last_seen"] = ts
        return inc

    for a in alerts:
        # Con varias reglas de Kibana activas (SSH, port scan, phishing...), `alerts` trae
        # TODAS mezcladas — no solo las de fuerza bruta. Sin este filtro, una alerta de otra
        # regla (ej. port scan T1046) se procesaría acá como si fuera un incidente SSH, con
        # 0 eventos reales y una IP que nunca hizo fuerza bruta.
        technique_id = (a.get("mitre") or {}).get("technique_id")
        if technique_id and technique_id not in _AUTH_MITRE_TECHNIQUES:
            continue
        # `source_ip` de una alerta solo viene completo cuando la regla agrupó
        # por el atacante. Si agrupó por host (ej. la regla A1, "5+ fallos contra
        # el mismo host"), el atacante no se conoce y la alerta aporta la VÍCTIMA
        # — `prepare-for-ia.py` la deja en `victim_host`.
        #
        # Antes se tomaba el valor agrupado como atacante en todos los casos, así
        # que una regla centrada en la víctima producía un incidente que acusaba
        # al host atacado. Es el mismo error que el hallazgo L-02, por la puerta
        # de las alertas en vez de la de los logs.
        ip = valid_ip(a.get("source_ip")) or IP_DESCONOCIDA
        inc = ensure(ip, a.get("timestamp", now_iso()))
        # Si varias reglas de Kibana disparan sobre la misma IP (ej. una atacante
        # activa una regla Low de línea base Y una Critical de compromiso), la
        # identidad del incidente (`rule_name`/`severity_siem`/`risk_score`) tiene
        # que ser la de la alerta MÁS GRAVE — no la última que devolvió
        # Elasticsearch. Con "última gana", un incidente que de verdad es crítico
        # podía terminar mostrando "Low" solo porque esa alerta llegó después en
        # la respuesta: el panel lo pinta con la severidad de la insignia, así que
        # perder la más grave acá degradaba el incidente en silencio.
        rango_actual = _RANGO_SEVERIDAD_SIEM.get((inc["severity_siem"] or "").lower(), -1)
        rango_nueva  = _RANGO_SEVERIDAD_SIEM.get((a.get("severity") or "").lower(), -1)
        if rango_nueva >= rango_actual:
            inc["rule_name"]     = a.get("rule_name") or inc["rule_name"]
            inc["severity_siem"] = a.get("severity") or inc["severity_siem"]
            inc["risk_score"]    = a.get("risk_score") or inc["risk_score"]
        inc["alert_event_count"] += a.get("event_count") or 0
        if ip != IP_DESCONOCIDA:
            inc["attacker_ips"].add(ip)

        victima = valid_ip(a.get("victim_host"))
        if victima:
            inc["victim_hosts"].add(victima)
        usuario_alerta = valid_username(a.get("target_user"))
        if usuario_alerta:
            inc["target_users"].add(usuario_alerta)

        if a.get("mitre"):
            inc["mitre"] = a["mitre"]

    for lg in logs:
        msg = lg.get("message", "") or ""
        # L-02: la IP del atacante sale del mensaje y define el incidente. `host_ip`
        # es la VÍCTIMA — usarla como clave era lo que partía el ataque en dos.
        m_ip = _FROM_IP_RE.search(msg)
        attacker_ip = valid_ip(m_ip.group(1)) if m_ip else None
        inc = ensure(attacker_ip or IP_DESCONOCIDA, lg.get("timestamp", now_iso()))
        if attacker_ip:
            inc["attacker_ips"].add(attacker_ip)

        victima = valid_ip(lg.get("host_ip"))
        if victima:
            inc["victim_hosts"].add(victima)

        m_user = _USER_RE.search(msg)
        if m_user:
            usuario = valid_username(m_user.group(1))
            if usuario:
                inc["target_users"].add(usuario)
        if len(inc["sample_messages"]) < 8:
            inc["sample_messages"].append(sanitize_for_prompt(msg))
        ts = lg.get("timestamp")
        if ts and len(inc["evidence"]) < 12:
            inc["evidence"].append({"ts": ts, "detail": sanitize_for_prompt(msg)})
        # L-01: una línea de log es un evento. Sin condición previa.
        inc["log_event_count"] += 1

    out: list[dict] = []
    for ip, inc in incidents.items():
        technique = (inc["mitre"] or {}).get("technique_id")
        rule_name = (inc["rule_name"] or "").lower()
        total = _total_eventos(inc)
        has_failed_pw = bool(inc["attacker_ips"]) or any(
            "failed password" in (e.get("detail", "").lower()) for e in inc["evidence"])
        rule_hint = any(k in rule_name for k in
                        ("brute", "fuerza bruta", "ssh", "auth", "password", "login"))
        # Si el SIEM ya disparó una alerta sobre fallos de auth, es un ataque confirmado:
        # el clasificador no debe degradarlo solo porque el conteo sea menor a su umbral.
        siem_confirmed = bool(inc["rule_name"]) and has_failed_pw
        is_brute = (technique == "T1110" or rule_hint or siem_confirmed
                    or total >= BRUTE_FORCE_THRESHOLD)
        attack_type = "ssh_brute_force" if is_brute else "suspicious_auth"
        factors = [f"{total} fallo(s) de autenticación registrados "
                   f"(umbral de fuerza bruta: {BRUTE_FORCE_THRESHOLD})"]
        if inc["victim_hosts"]:
            factors.append(f"Host(s) atacado(s): {', '.join(sorted(inc['victim_hosts']))}")
        if not is_brute:
            detail = (f"{total} fallos de autenticación: por debajo del umbral de "
                      f"{BRUTE_FORCE_THRESHOLD} y sin alerta del SIEM; requiere revisión manual.")
            factors.append("Sin confirmación de ninguna regla activa del SIEM")
            factors.append("Falso positivo: MEDIA — podría ser un usuario que se equivocó de contraseña")
        elif total >= BRUTE_FORCE_THRESHOLD:
            detail = (f"{total} fallos de autenticación desde una misma IP superan el umbral "
                      f"de {BRUTE_FORCE_THRESHOLD}; patrón de fuerza bruta automatizada (T1110).")
            factors.append("Volumen muy por encima del umbral: descarta un error humano puntual")
            if total >= CRITICAL_FAILURE_COUNT:
                factors.append(f"Volumen extremo (≥{CRITICAL_FAILURE_COUNT}) → severidad elevada a CRÍTICA")
            factors.append("Falso positivo: BAJA — este volumen es infrecuente en tráfico legítimo")
        else:
            usr = next(iter(sorted(inc["target_users"])), "un usuario")
            detail = (f"El SIEM disparó la regla '{inc['rule_name']}': {total} fallos de "
                      f"autenticación desde {ip} contra {usr}; patrón consistente con "
                      f"fuerza bruta SSH (MITRE T1110), confirmado por el SIEM.")
            factors.append(f"Confirmado por una regla activa del SIEM: '{inc['rule_name']}'")
            factors.append("El clasificador no degrada la severidad solo porque el conteo "
                            "sea bajo, ya que el SIEM ya corroboró el patrón de forma independiente")
            factors.append("Falso positivo: BAJA — confirmado por dos capas de detección (SIEM + clasificador)")
        classification = _classification(attack_type, total, detail, factors)

        attacker_ip = resolver_ip_atacante(sorted(inc["attacker_ips"]), ip)
        user = next(iter(sorted(inc["target_users"])), None)
        incident_id = _incident_id("AUTH", ip, inc["first_seen"])
        actions = _finalize(incident_id, _playbook(
            attack_type, attacker_ip, user,
            magnitud_critica=total >= CRITICAL_FAILURE_COUNT))

        if not inc["mitre"] and classification["mitre_technique"]:
            inc["mitre"] = {"tactic": "Credential Access", "technique": "Brute Force",
                            "technique_id": classification["mitre_technique"]}

        out.append(Incident(
            incident_id=incident_id,
            # `source_ip` es siempre el ATACANTE (antes, en la rama de logs, era
            # la víctima). `victim_hosts` lleva los hosts atacados.
            source_ip=ip,
            attacker_ips=sorted(inc["attacker_ips"]),
            victim_hosts=sorted(inc["victim_hosts"]),
            target_users=sorted(inc["target_users"]),
            first_seen=inc["first_seen"], last_seen=inc["last_seen"],
            # Si llegó una alerta, `rule_name` es el de la regla que disparó.
            detection_source="elastic" if inc["rule_name"] else "clasificador",
            rule_name=inc["rule_name"], severity_siem=inc["severity_siem"],
            risk_score=inc["risk_score"], event_count=total,
            log_event_count=inc["log_event_count"],
            alert_event_count=inc["alert_event_count"],
            mitre=inc["mitre"], sample_messages=inc["sample_messages"],
            evidence=inc["evidence"],
            classification=classification,
            recommended_actions=actions,
        ).to_dict())
    return out


def _alertas_por_ip(alerts: list[dict], tecnicas: set[str]) -> dict[str, list[dict]]:
    """Alertas de Kibana de una técnica dada, agrupadas por `source_ip`.

    `port_scan` y `phishing` se detectan leyendo `network_logs/` directamente
    (ver docstring del módulo) — nunca consultaban las alertas B1-B4/C1-C3 que sí
    existen en Kibana para esa misma técnica, así que un evento detectado por acá
    aparecía siempre como "sin regla SIEM" aunque la regla hubiera disparado de
    verdad. `source_ip` en la alerta ya sale del mismo campo crudo del evento que
    usa el detector para agrupar (ver `parse_alerts`), así que agrupar por ahí
    alcanza para emparejar sin reinterpretar roles.
    """
    agrupadas: dict[str, list[dict]] = {}
    for a in alerts:
        technique_id = (a.get("mitre") or {}).get("technique_id")
        if technique_id not in tecnicas:
            continue
        ip = valid_ip(a.get("source_ip"))
        if not ip:
            continue
        agrupadas.setdefault(ip, []).append(a)
    return agrupadas


def _regla_mas_severa(alertas_por_ip: dict[str, list[dict]], ip: str) -> tuple[str | None, str | None, int | None]:
    """De las alertas que coinciden con esta IP, la identidad de la MÁS GRAVE.

    Mismo criterio que la fusión por IP de `detect_auth_incidents`: con varias
    reglas activas sobre la misma IP, la más grave manda, no la primera o la
    última que devolvió Elasticsearch.
    """
    mejor: dict | None = None
    mejor_rango = -1
    for a in alertas_por_ip.get(ip, []):
        rango = _RANGO_SEVERIDAD_SIEM.get((a.get("severity") or "").lower(), -1)
        if rango >= mejor_rango:
            mejor_rango = rango
            mejor = a
    if mejor is None:
        return None, None, None
    return mejor.get("rule_name"), mejor.get("severity"), mejor.get("risk_score")


# ─── Detección: port scan (eventos de red) ───────────────────────────────────

def detect_port_scans(events: list[dict], alerts: list[dict] | None = None) -> list[dict]:
    flows = [e for e in events if e.get("event_type") in ("network_flow", "port_scan")
             and e.get("source_ip") and e.get("dest_port") is not None]
    by_ip: dict[str, dict] = {}
    for e in flows:
        # S-01: `source_ip` viene de un log y no es confiable. Un valor que no es una
        # IP se agrupa bajo el sentinela en vez de entrar crudo al incident_id (que
        # termina renderizado en el panel del analista) o a un comando sugerido.
        ip = valid_ip(e["source_ip"]) or IP_DESCONOCIDA
        b = by_ip.setdefault(ip, {"ports": set(), "dests": set(), "ts": [], "count": 0, "evidence": []})
        b["ports"].add(e.get("dest_port"))
        if e.get("dest_ip"):
            b["dests"].add(e["dest_ip"])
        if e.get("@timestamp"):
            b["ts"].append(e["@timestamp"])
            if len(b["evidence"]) < 12:
                b["evidence"].append({"ts": e["@timestamp"],
                    "detail": f"probe → {e.get('dest_ip','?')}:{e.get('dest_port')}/{e.get('protocol','tcp')}"})
        b["count"] += 1

    alertas_por_ip = _alertas_por_ip(alerts or [], _PORT_SCAN_MITRE_TECHNIQUES)

    out: list[dict] = []
    for ip, b in by_ip.items():
        if len(b["ports"]) < PORT_SCAN_DISTINCT_PORTS:
            continue
        ts_sorted = sorted(b["ts"], key=ts_ordenable) or [now_iso()]
        ip_atacante = valid_ip(ip)
        # D-11 sigue vigente: `rule_name` solo se completa si de verdad hay una
        # alerta de Kibana (B1-B4) para esta IP — nunca un nombre inventado. Si
        # ninguna regla disparó todavía (ej. Filebeat no llegó a indexar, o las
        # reglas están deshabilitadas), sigue cayendo a "clasificador", como antes.
        rule_name, severity_siem, risk_score = _regla_mas_severa(alertas_por_ip, ip)
        detail = (f"{len(b['ports'])} puertos distintos sondeados desde {ip} "
                  f"(umbral {PORT_SCAN_DISTINCT_PORTS}); patrón de reconocimiento de red.")
        factors = [
            f"{len(b['ports'])} puerto(s) distinto(s) sondeado(s) (umbral: {PORT_SCAN_DISTINCT_PORTS})",
            f"{len(b['dests'])} host(s) de destino distintos sondeados",
            (f"Confirmado por una regla activa del SIEM: '{rule_name}'" if rule_name
             else "Ninguna regla de Kibana disparó todavía para esta IP "
                  "→ la única confirmación es la del clasificador"),
            "Patrón de barrido secuencial de puertos, poco común en tráfico legítimo",
            "Falso positivo: BAJA — salvo que la IP sea un scanner de vulnerabilidades autorizado",
        ]
        classification = _classification("port_scan", len(b["ports"]), detail, factors)
        incident_id = _incident_id("SCAN", ip, ts_sorted[0])
        actions = _finalize(incident_id, _playbook("port_scan", ip_atacante, None))
        out.append(Incident(
            incident_id=incident_id, source_ip=ip,
            attacker_ips=[ip_atacante] if ip_atacante else [],
            victim_hosts=sorted(b["dests"]),
            first_seen=ts_sorted[0], last_seen=ts_sorted[-1],
            detection_source="elastic" if rule_name else "clasificador",
            rule_name=rule_name, severity_siem=severity_siem, risk_score=risk_score,
            event_count=b["count"], log_event_count=b["count"],
            mitre={"tactic": "Discovery", "technique": "Network Service Discovery",
                   "technique_id": "T1046"},
            sample_messages=[sanitize_for_prompt(
                f"scan {ip} -> {', '.join(sorted(b['dests']))} puertos {sorted(b['ports'])[:12]}")],
            evidence=b["evidence"],
            classification=classification,
            recommended_actions=actions,
            extras={
                "scanned_ports": sorted(p for p in b["ports"] if p is not None),
                "target_hosts": sorted(b["dests"]),
            },
        ).to_dict())
    return out


# ─── Detección: phishing / credential harvesting (eventos web) ───────────────

def detect_phishing(events: list[dict], alerts: list[dict] | None = None) -> list[dict]:
    subs = [e for e in events if e.get("event_type") == "http_request"
            and (e.get("credential_submission") or e.get("password_submitted"))]
    by_ip: dict[str, dict] = {}
    for e in subs:
        # S-01: mismo criterio que en port scan — `source_ip` y `username` salen de
        # un log controlable por el atacante y no pueden entrar crudos.
        ip = valid_ip(e.get("source_ip")) or IP_DESCONOCIDA
        b = by_ip.setdefault(ip, {"users": set(), "urls": set(), "dests": set(),
                                   "ts": [], "count": 0, "evidence": [],
                                   "users_invalidos": 0})
        usuario = valid_username(e.get("username"))
        if usuario:
            b["users"].add(usuario)
        elif e.get("username"):
            # No se descarta el evento (la detección sigue siendo válida): se registra
            # que hubo un usuario con formato inesperado, sin arrastrar su contenido.
            b["users_invalidos"] = b.get("users_invalidos", 0) + 1
        if e.get("url"):
            b["urls"].add(e["url"])
        if e.get("dest_ip"):
            b["dests"].add(e["dest_ip"])
        if e.get("@timestamp"):
            b["ts"].append(e["@timestamp"])
            if len(b["evidence"]) < 12:
                b["evidence"].append({"ts": e["@timestamp"],
                    "detail": f"{e.get('http_method','POST')} {e.get('url','/login')} "
                              f"(user={e.get('username','?')}, creds={'sí' if e.get('credential_submission') or e.get('password_submitted') else 'no'})"})
        b["count"] += 1

    alertas_por_ip = _alertas_por_ip(alerts or [], _PHISHING_MITRE_TECHNIQUES)

    out: list[dict] = []
    for ip, b in by_ip.items():
        ts_sorted = sorted(b["ts"], key=ts_ordenable) or [now_iso()]
        users = ", ".join(sorted(b["users"])) or "usuario(s) desconocido(s)"
        # D-11 sigue vigente: nunca se inventa un nombre de regla. Si ninguna de
        # C1-C3 disparó todavía para esta IP, el factor lo dice tal cual.
        rule_name, severity_siem, risk_score = _regla_mas_severa(alertas_por_ip, ip)
        detail = (f"{b['count']} envío(s) de credenciales hacia una página de login "
                  f"sospechosa ({', '.join(sorted(b['urls'])) or '/login'}); posible "
                  f"captura de credenciales (phishing).")
        factors = [
            f"{b['count']} envío(s) de credenciales detectado(s) hacia una URL marcada como sospechosa",
            f"{len(b['users'])} usuario(s) distinto(s) afectado(s)",
            (f"Confirmado por una regla activa del SIEM: '{rule_name}'" if rule_name
             else "Ninguna regla de Kibana disparó todavía para esta IP "
                  "→ la única confirmación es la del clasificador"),
            "Falso positivo: MEDIA — depende de qué tan confiable sea la fuente que marcó la URL como sospechosa",
        ]
        classification = _classification("credential_harvesting", b["count"], detail, factors)
        incident_id = _incident_id("PHISH", ip, ts_sorted[0])
        user = next(iter(sorted(b["users"])), None)
        ip_servidor = resolver_ip_atacante(sorted(b["dests"]), valid_ip(ip))
        actions = _finalize(incident_id, _playbook("credential_harvesting", ip_servidor, user))
        out.append(Incident(
            incident_id=incident_id, source_ip=ip,
            attacker_ips=sorted(b["dests"]) or ([ip] if valid_ip(ip) else []),
            target_users=sorted(b["users"]),
            first_seen=ts_sorted[0], last_seen=ts_sorted[-1],
            detection_source="elastic" if rule_name else "clasificador",
            rule_name=rule_name, severity_siem=severity_siem, risk_score=risk_score,
            event_count=b["count"], log_event_count=b["count"],
            mitre={"tactic": "Initial Access", "technique": "Phishing",
                   "technique_id": "T1566"},
            sample_messages=[sanitize_for_prompt(
                f"POST {', '.join(sorted(b['urls']))} usuario={users} desde {ip}")],
            evidence=b["evidence"],
            classification=classification,
            recommended_actions=actions,
            extras={"phishing_urls": sorted(b["urls"])},
        ).to_dict())
    return out


# ─── Correlación entre incidentes (campañas) ─────────────────────────────────

def _link_campaigns(incidents: list[dict]) -> None:
    """Vincula incidentes que comparten al menos una IP DE ATACANTE,
    aunque vengan de detecciones distintas (ej. la misma IP hace port scan y después
    fuerza bruta SSH). Muta cada incidente in-place agregando `campaign_id` y
    `related_incidents`. Es la respuesta, en la capa Python, a la misma idea que las
    reglas EQL de secuencia resuelven dentro de Kibana: una IP atacando en varios
    frentes es más grave que la suma de sus incidentes sueltos.
    """
    ip_to_idxs: dict[str, list[int]] = {}
    for idx, inc in enumerate(incidents):
        # L-04: SOLO IPs de atacante. Antes se incluía `source_ip`, que en los
        # incidentes de phishing es la VÍCTIMA que envió sus credenciales y, antes
        # de L-02, también era la víctima en los de autenticación. Correlacionar
        # por ahí vinculaba a un atacante con el host que estaba atacando, como si
        # fueran dos frentes de la misma campaña.
        ips = {ip for ip in (inc.get("attacker_ips") or []) if ip and ip != IP_DESCONOCIDA}
        for ip in ips:
            ip_to_idxs.setdefault(ip, []).append(idx)

    parent = list(range(len(incidents)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    shared_ip_by_idx: dict[int, set[str]] = {i: set() for i in range(len(incidents))}
    for ip, idxs in ip_to_idxs.items():
        if len(idxs) > 1:
            for i in idxs:
                shared_ip_by_idx[i].add(ip)
        for i in idxs[1:]:
            union(idxs[0], i)

    groups: dict[int, list[int]] = {}
    for idx in range(len(incidents)):
        groups.setdefault(find(idx), []).append(idx)

    for idxs in groups.values():
        if len(idxs) < 2:
            incidents[idxs[0]]["campaign_id"] = None
            incidents[idxs[0]]["related_incidents"] = []
            incidents[idxs[0]]["campaign_shared_ips"] = []
            continue
        ids_sorted = sorted(incidents[i]["incident_id"] for i in idxs)
        campaign_id = "CAMP-" + _hash_corto("|".join(ids_sorted))
        for i in idxs:
            incidents[i]["campaign_id"] = campaign_id
            incidents[i]["related_incidents"] = sorted(
                incidents[j]["incident_id"] for j in idxs if j != i)
            incidents[i]["campaign_shared_ips"] = sorted(shared_ip_by_idx[i])


# ─── Orquestación ────────────────────────────────────────────────────────────

def classify(siem_data: dict, network_events: list[dict] | None = None) -> list[dict]:
    network_events = network_events or []
    alerts = siem_data.get("alerts", [])
    incidents = (
        detect_auth_incidents(siem_data)
        + detect_port_scans(network_events, alerts)
        + detect_phishing(network_events, alerts)
    )
    incidents.sort(key=lambda x: x["event_count"], reverse=True)
    _link_campaigns(incidents)
    return incidents


def main() -> None:
    print("[Agente 1 - Clasificador] Aplicando reglas determinísticas...")
    try:
        siem_data = load_json(SIEM_FILE)
    except FileNotFoundError:
        # Sin captura previa de Elasticsearch (nunca corrió prepare-for-ia.py con el stack
        # arriba): no es un error fatal, clasificamos solo a partir de network_logs/ (modo
        # offline puro, ej. justo después de clonar el repo).
        print(f"[INFO] No se encontró '{SIEM_FILE}' (sin captura previa de Elasticsearch). "
              f"Clasificando solo a partir de network_logs/.")
        siem_data = {}
    # B-04: antes esto leía también `siem_data["network_events"]` y `["web_events"]`,
    # dos claves que `prepare-for-ia.py` NUNCA genera — la rama siempre devolvía []
    # y aparentaba una ruta de ingesta que no existe. `network_logs/` es la única
    # fuente real de eventos de red/web (no hay Suricata; ver docs/01).
    network_events = read_network_logs("network_logs")

    incidents = classify(siem_data, network_events)

    report = {
        "generated_at": now_iso(),
        "source": SIEM_FILE,
        "incident_count": len(incidents),
        "incidents": incidents,
    }
    write_json(INCIDENTS_FILE, report)

    print(f"  Incidentes detectados: {len(incidents)}")
    for inc in incidents:
        c = inc["classification"]
        print(f"   • {inc['incident_id']}: {c['attack_type']} "
              f"[{_SEV_LABEL_EN.get(c['severity'], c['severity'].upper())}] — {inc['event_count']} eventos")
    print(f"[OK] Clasificación guardada en '{INCIDENTS_FILE}'")


if __name__ == "__main__":
    main()
