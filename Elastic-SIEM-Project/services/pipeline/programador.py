#!/usr/bin/env python3
"""Corrida programada del pipeline (sección 7.9.2 de la ERS).

Sin esto el ciclo solo corría a mano (`./scripts/siem.sh pipeline`): una alerta
nueva de Kibana no llegaba al panel hasta que alguien se acordara de dispararlo.
Ahora el servicio pipeline corre un ciclo cada `SIEM_PIPELINE_INTERVALO`
segundos (docker-compose.yml lo fija en 120).

Usa el mismo `ejecutar_ciclo()` que la API, y por lo tanto el mismo candado: si
un ciclo manual está en curso, la corrida programada de ese turno se saltea en
vez de esperar o encimarse. Un ciclo que falla no detiene el programador: el
reporte anterior queda intacto (lo garantiza el orquestador) y se reintenta en
el turno siguiente.

Apagado por defecto (`SIEM_PIPELINE_INTERVALO` vacío o `0`): las pruebas y las
herramientas de línea de comandos importan este servicio y no deben disparar
ciclos por su cuenta.
"""

from __future__ import annotations

import os
import threading

from orquestador import CicloEnCurso, ErrorDeEtapa, ejecutar_ciclo

VARIABLE = "SIEM_PIPELINE_INTERVALO"

# Un ciclo con el LLM encendido puede tardar más de un minuto; por debajo de
# esto las corridas se pisarían entre sí y solo sumarían ruido al historial.
INTERVALO_MINIMO = 30

_parar = threading.Event()
_hilo: threading.Thread | None = None


def intervalo_configurado() -> int:
    """Segundos entre corridas, o 0 si la corrida programada está apagada.

    Un valor inválido o por debajo del mínimo es un error de configuración: se
    dice en vez de adivinar qué quiso poner quien desplegó.
    """
    crudo = os.getenv(VARIABLE, "").strip()
    if crudo in ("", "0"):
        return 0
    try:
        segundos = int(crudo)
    except ValueError:
        raise ValueError(f"{VARIABLE} tiene que ser un número de segundos, no {crudo!r}") from None
    if segundos < INTERVALO_MINIMO:
        raise ValueError(f"{VARIABLE}={segundos}: el mínimo es {INTERVALO_MINIMO} segundos (0 = apagado)")
    return segundos


def correr_un_turno() -> str:
    """Un turno del programador. Devuelve qué pasó, para el log y las pruebas."""
    try:
        resultado = ejecutar_ciclo()
    except CicloEnCurso:
        return "salteado: ya había un ciclo en curso"
    except ErrorDeEtapa as e:
        return f"falló: {e}"
    return f"ok: {len(resultado['report'].get('incidents', []))} incidente(s)"


def _bucle(intervalo: int) -> None:
    # Primero espera: al arrancar el contenedor, las dependencias recién pasan
    # su healthcheck y conviene darle un margen al stack.
    while not _parar.wait(intervalo):
        print(f"[programador] corrida automática — {correr_un_turno()}", flush=True)


def iniciar() -> bool:
    """Arranca el hilo si la corrida programada está encendida. Idempotente."""
    global _hilo
    intervalo = intervalo_configurado()
    if intervalo == 0 or (_hilo is not None and _hilo.is_alive()):
        return False
    _parar.clear()
    _hilo = threading.Thread(target=_bucle, args=(intervalo,), name="programador-pipeline",
                             daemon=True)
    _hilo.start()
    print(f"[programador] pipeline automático cada {intervalo} s", flush=True)
    return True


def detener() -> None:
    _parar.set()
