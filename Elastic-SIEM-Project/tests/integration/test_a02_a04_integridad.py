"""Regresión de **A-02, A-03 y A-04** — integridad real del registro de auditoría.

Hasta la Fase 2, "append-only e inmutable" describía una intención del diseño:
nada impedía abrir `decisions.jsonl` y editar una decisión, dos hilos de Flask
podían entrelazar escrituras, y un corte de energía podía perder la última.

Ahora son propiedades del sistema:

- **A-02** — `flock(LOCK_EX)` + `flush()` + `fsync()`, y el archivo se crea con
  permisos `0600`.
- **A-03** — el `action_id` deriva del contenido de la acción, no de su posición,
  así que reordenar u omitir una acción no reapunta las decisiones históricas.
- **A-04** — cada registro lleva el SHA-256 del anterior en `prev_hash`. Editar
  o borrar una línea del medio rompe la cadena y `audit_verify.py` lo detecta.

Reemplazan a los congelados `test_A02_*`, `test_A03_*`, `test_A04_*` y
`test_A_permisos_*`.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import siem_lib

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


# ─── A-02 · escritura atómica, durable y con permisos ────────────────────────

def test_el_registro_se_crea_con_permisos_restrictivos(sandbox):
    """La auditoría no la lee cualquier usuario del sistema."""
    ruta = sandbox / "decisions.jsonl"
    siem_lib.append_jsonl(ruta, {"decision": "approved"})
    assert ruta.stat().st_mode & 0o777 == 0o600


def test_append_usa_bloqueo_y_fsync():
    """Verificación estructural: las tres llamadas están en el código.

    Complementa a las de comportamiento — la durabilidad ante un corte de
    energía no se puede provocar en una prueba, pero sí se puede exigir que el
    código la pida.
    """
    fuente = (PROJECT_ROOT / "siem_lib.py").read_text(encoding="utf-8")
    cuerpo = fuente.split("def append_jsonl")[1].split("\ndef ")[0]
    assert "flock" in cuerpo and "LOCK_EX" in cuerpo
    assert "fsync" in cuerpo
    assert "O_APPEND" in cuerpo


def test_escrituras_concurrentes_no_se_entrelazan(sandbox):
    """20 decisiones simultáneas ⇒ 20 líneas bien formadas, ninguna corrupta.

    Flask atiende en varios hilos: dos analistas decidiendo a la vez comparten
    proceso. Sin `flock` las escrituras podían intercalarse a mitad de línea.
    """
    ruta = sandbox / "decisions.jsonl"

    def escribir(n: int) -> None:
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved",
                                     "note": "x" * 200})

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(escribir, range(20)))

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    assert len(lineas) == 20
    for linea in lineas:
        json.loads(linea)  # ninguna línea partida por el medio
    assert sorted(json.loads(x)["n"] for x in lineas) == list(range(20))


def test_escrituras_concurrentes_mantienen_la_cadena(sandbox):
    """El `prev_hash` se calcula CON el lock tomado, no antes.

    Si se leyera el último hash fuera del bloqueo, dos escrituras simultáneas
    encadenarían sobre el mismo eslabón y la cadena quedaría bifurcada.
    """
    ruta = sandbox / "decisions.jsonl"

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda n: siem_lib.append_jsonl(ruta, {"n": n}), range(20)))

    assert siem_lib.verificar_cadena(ruta)["chain_ok"] is True


# ─── A-04 · la cadena de hashes ──────────────────────────────────────────────

def test_cada_registro_lleva_el_hash_del_anterior(sandbox):
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})

    registros = siem_lib.read_jsonl(ruta)
    assert registros[0]["prev_hash"] == siem_lib.GENESIS_HASH
    for anterior, siguiente in zip(registros, registros[1:], strict=False):
        assert siguiente["prev_hash"] == siem_lib._hash_registro(anterior)


def test_una_cadena_intacta_se_verifica(sandbox):
    ruta = sandbox / "decisions.jsonl"
    for n in range(5):
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved"})

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado == {"estado": "ok", "chain_ok": True, "records": 5,
                         "first_broken": None, "reason": None}


def test_editar_una_linea_del_medio_rompe_la_cadena(sandbox):
    """El caso que antes pasaba inadvertido: cambiar una decisión ya tomada."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(5):
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved"})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    manipulado = json.loads(lineas[2])
    manipulado["decision"] = "dismissed"
    lineas[2] = json.dumps(manipulado, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["chain_ok"] is False
    assert resultado["first_broken"] == 4, "se detecta en el eslabón siguiente"
    assert "modificado o eliminado" in resultado["reason"]


def test_borrar_una_linea_rompe_la_cadena(sandbox):
    ruta = sandbox / "decisions.jsonl"
    for n in range(5):
        siem_lib.append_jsonl(ruta, {"n": n})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    del lineas[2]
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(ruta)["chain_ok"] is False


def test_una_linea_corrupta_rompe_la_cadena(sandbox):
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})
    with open(ruta, "a", encoding="utf-8") as f:
        f.write("{esto no es json\n")

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["chain_ok"] is False
    assert resultado["reason"] == "línea malformada"


def test_agregar_al_final_no_rompe_nada(sandbox):
    """Append legítimo: la cadena sigue válida, que es el punto."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})
    assert siem_lib.verificar_cadena(ruta)["chain_ok"]

    siem_lib.append_jsonl(ruta, {"n": 99})
    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["chain_ok"] and resultado["records"] == 4


def test_un_registro_pegado_a_mano_al_final_no_pasa(sandbox):
    """Ni siquiera agregar al final funciona sin conocer el hash previo."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})

    with open(ruta, "a", encoding="utf-8") as f:
        f.write(json.dumps({"n": 4, "decision": "approved",
                            "prev_hash": "0" * 64}) + "\n")

    assert siem_lib.verificar_cadena(ruta)["chain_ok"] is False


def test_registro_vacio_o_inexistente_es_valido(sandbox):
    assert siem_lib.verificar_cadena(sandbox / "no-existe.jsonl")["chain_ok"]
    (sandbox / "vacio.jsonl").write_text("", encoding="utf-8")
    assert siem_lib.verificar_cadena(sandbox / "vacio.jsonl")["chain_ok"]


# ─── A-04 · el verificador como herramienta ──────────────────────────────────

def _correr_verificador(directorio: Path, *args: str) -> subprocess.CompletedProcess:
    entorno = {**os.environ, "PYTHONPATH": str(PROJECT_ROOT)}
    return subprocess.run(
        [sys.executable, str(PROJECT_ROOT / "audit_verify.py"), *args],
        cwd=directorio, capture_output=True, text=True, timeout=60,
        env=entorno, check=False)


def test_audit_verify_sale_con_cero_si_la_cadena_esta_intacta(sandbox):
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved", "analyst": "ana"})

    resultado = _correr_verificador(sandbox)
    assert resultado.returncode == 0
    assert "Cadena intacta" in resultado.stdout


def test_audit_verify_sale_con_uno_si_esta_rota(sandbox):
    """Código de salida 1: sirve como puerta en CI."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})
    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    lineas[1] = json.dumps({"n": "manipulado", "prev_hash": "0" * 64})
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    resultado = _correr_verificador(sandbox)
    assert resultado.returncode == 1
    assert "CADENA ROTA" in resultado.stdout
    assert "escalar el hallazgo" in resultado.stdout


def test_audit_verify_tiene_salida_json(sandbox):
    ruta = sandbox / "decisions.jsonl"
    siem_lib.append_jsonl(ruta, {"decision": "approved", "analyst": "ana"})

    resultado = _correr_verificador(sandbox, "--json")
    datos = json.loads(resultado.stdout)
    assert datos[0]["chain_ok"] is True
    assert datos[0]["records"] == 1


def test_audit_verify_no_modifica_nada(sandbox):
    """Un verificador que pudiera reparar el archivo que audita no serviría."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})
    antes = ruta.read_bytes()

    _correr_verificador(sandbox)
    assert ruta.read_bytes() == antes


def test_sin_registros_no_es_una_falla(sandbox):
    """Un proyecto recién clonado no tiene decisiones: eso no es un error."""
    resultado = _correr_verificador(sandbox)
    assert resultado.returncode == 0
    assert "no existe todavía" in resultado.stdout


# ─── A-03 · action_id estable ante cambios del playbook ──────────────────────

def test_el_action_id_deriva_del_contenido(siem_clean):
    """Mismo contenido ⇒ mismo id, sin importar la posición en la lista."""
    import classifier

    inc = classifier.detect_auth_incidents(siem_clean)[0]
    original = {a["accion"]: a["action_id"] for a in inc["recommended_actions"]}

    reordenado = classifier._finalize(
        inc["incident_id"], list(reversed(inc["recommended_actions"])))
    despues = {a["accion"]: a["action_id"] for a in reordenado}

    assert original == despues, "reordenar el playbook cambió los identificadores"


def test_omitir_una_accion_no_reapunta_a_las_otras():
    """El caso real que rompía A-03, ahora que S-01 omite acciones.

    Si falta el usuario, el playbook de fuerza bruta ya no incluye el `passwd`.
    Con ids posicionales, la decisión registrada sobre `-a4` (fail2ban) pasaba a
    apuntar al `-a3` de otra corrida. Y el registro es inmutable: no hay forma de
    corregir esa reasignación después.
    """
    import classifier

    completo = classifier._playbook("ssh_brute_force", "203.0.113.7", "testuser")
    sin_usuario = classifier._playbook("ssh_brute_force", "203.0.113.7", None)

    classifier._finalize("INC-X", completo)
    classifier._finalize("INC-X", sin_usuario)

    ids_completo = {a["accion"]: a["action_id"] for a in completo}
    for accion in sin_usuario:
        if accion["accion"] in ids_completo:
            assert accion["action_id"] == ids_completo[accion["accion"]]


def test_los_action_id_son_unicos_dentro_del_incidente(incidents):
    for inc in incidents:
        ids = [a["action_id"] for a in inc["recommended_actions"]]
        assert len(ids) == len(set(ids))


def test_el_action_id_no_depende_del_orden_declarado():
    """Aunque el catálogo se reescriba, una acción conserva su identidad."""
    import classifier

    a = classifier._finalize("INC-X", [
        {"accion": "Bloquear la IP", "comando_sugerido": "sudo ufw deny from 1.2.3.4"},
        {"accion": "Rotar credenciales", "comando_sugerido": "sudo passwd bob"}])
    b = classifier._finalize("INC-X", [
        {"accion": "Rotar credenciales", "comando_sugerido": "sudo passwd bob"},
        {"accion": "Bloquear la IP", "comando_sugerido": "sudo ufw deny from 1.2.3.4"}])

    assert a[0]["action_id"] == b[1]["action_id"]
    assert a[1]["action_id"] == b[0]["action_id"]


# ─── Integración con el flujo real de decisiones ─────────────────────────────

def test_las_decisiones_del_dashboard_quedan_encadenadas(client, sandbox_con_incidentes):
    """El flujo completo: aprobar desde la API deja una cadena verificable."""
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    for accion in inc["recommended_actions"]:
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": accion["action_id"],
            "decision": "approved"})

    resultado = siem_lib.verificar_cadena(sandbox_con_incidentes / "decisions.jsonl")
    assert resultado["chain_ok"] is True
    assert resultado["records"] == len(inc["recommended_actions"])


def test_manipular_una_decision_se_detecta_desde_el_flujo_real(client,
                                                               sandbox_con_incidentes):
    """Alguien edita a mano una decisión aprobada para que parezca descartada."""
    ruta = sandbox_con_incidentes / "decisions.jsonl"
    inc = client.get("/api/incidents").get_json()["incidents"][0]
    for accion in inc["recommended_actions"][:3]:
        client.post("/api/decision", json={
            "incident_id": inc["incident_id"], "action_id": accion["action_id"],
            "decision": "approved"})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    falsificado = json.loads(lineas[0])
    falsificado["decision"] = "dismissed"
    falsificado["analyst"] = "otro-analista"
    lineas[0] = json.dumps(falsificado, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(ruta)["chain_ok"] is False


@pytest.mark.parametrize("campo", ["decision", "analyst", "ts", "note", "incident_id"])
def test_cambiar_cualquier_campo_rompe_la_cadena(sandbox, campo):
    """La protección no depende de qué campo se toque."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {
            "ts": f"2026-09-16T10:0{n}:00+00:00", "incident_id": f"INC-{n}",
            "decision": "approved", "analyst": "ana", "note": ""})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    registro = json.loads(lineas[0])
    registro[campo] = "MODIFICADO"
    lineas[0] = json.dumps(registro, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(ruta)["chain_ok"] is False


# ─── Registros heredados: no verificables ≠ manipulados ──────────────────────
#
# Encontrado al correr `audit_verify.py` sobre los datos reales del proyecto: las
# 27 decisiones previas a la Fase 2 no tienen `prev_hash`, y la primera versión
# las reportaba como "CADENA ROTA · el registro fue modificado después de
# escribirse". Es falso y además contraproducente: una alerta que aparece siempre
# y siempre es un falso positivo enseña a ignorar la herramienta — el mismo
# problema de alert fatigue que el proyecto entero intenta evitar.

def _escribir_sin_encadenar(ruta, cantidad: int) -> None:
    """Simula el formato anterior a la Fase 2 (sin `prev_hash`)."""
    with open(ruta, "w", encoding="utf-8") as f:
        for n in range(cantidad):
            f.write(json.dumps({"ts": f"2026-08-0{n+1}T10:00:00+00:00",
                                "incident_id": f"INC-{n}", "decision": "approved",
                                "analyst": "analista-soc"}) + "\n")


def test_un_registro_heredado_no_se_reporta_como_manipulado(sandbox):
    ruta = sandbox / "decisions.jsonl"
    _escribir_sin_encadenar(ruta, 5)

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["estado"] == "heredado"
    assert resultado["records"] == 5
    assert resultado["first_broken"] is None
    assert "no hay indicio de manipulación" in resultado["reason"]


def test_un_registro_heredado_no_hace_fallar_al_verificador(sandbox):
    """Exit 0: no es una falla de CI, es un estado a resolver archivando."""
    _escribir_sin_encadenar(sandbox / "decisions.jsonl", 3)

    resultado = _correr_verificador(sandbox, "decisions.jsonl")
    assert resultado.returncode == 0
    assert "SIN encadenar" in resultado.stdout
    assert "NO hay indicio de manipulación" in resultado.stdout
    assert "CADENA ROTA" not in resultado.stdout


def test_quitar_prev_hash_a_un_registro_si_es_manipulacion(sandbox):
    """La distinción tiene que resistir el abuso.

    Si borrar el campo bastara para pasar por "heredado", cualquiera podría
    evadir la detección quitándoselo al registro que quiere alterar.
    """
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    sin_campo = json.loads(lineas[2])
    del sin_campo["prev_hash"]
    lineas[2] = json.dumps(sin_campo, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["estado"] == "roto"
    assert "el campo fue eliminado" in resultado["reason"]


def test_quitar_prev_hash_al_primero_tampoco_alcanza(sandbox):
    """Aunque se ataque el primer registro, los siguientes delatan el cambio."""
    ruta = sandbox / "decisions.jsonl"
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    sin_campo = json.loads(lineas[0])
    del sin_campo["prev_hash"]
    lineas[0] = json.dumps(sin_campo, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(ruta)["estado"] == "roto"


def test_decisiones_nuevas_sobre_un_registro_heredado_se_encadenan(sandbox):
    """El caso de la migración: se sigue escribiendo sobre el archivo viejo."""
    ruta = sandbox / "decisions.jsonl"
    _escribir_sin_encadenar(ruta, 3)
    assert siem_lib.verificar_cadena(ruta)["estado"] == "heredado"

    for n in range(2):
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved"})

    resultado = siem_lib.verificar_cadena(ruta)
    assert resultado["estado"] == "ok"
    assert resultado["records"] == 5
    assert "3 registro(s) heredados al inicio" in resultado["reason"]


def test_manipular_el_tramo_encadenado_tras_uno_heredado_se_detecta(sandbox):
    """La protección vale para el tramo nuevo aunque el archivo arranque viejo."""
    ruta = sandbox / "decisions.jsonl"
    _escribir_sin_encadenar(ruta, 2)
    for n in range(3):
        siem_lib.append_jsonl(ruta, {"n": n, "decision": "approved"})

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    manipulado = json.loads(lineas[3])
    manipulado["decision"] = "dismissed"
    lineas[3] = json.dumps(manipulado, ensure_ascii=False)
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(ruta)["estado"] == "roto"


def test_el_api_tambien_distingue_los_tres_estados(client_como, sandbox_con_incidentes):
    """El panel muestra el mismo criterio que la herramienta de consola.

    Lo consulta el rol `auditor`: verificar la cadena es su capacidad
    distintiva, separada de la de decidir (ver test_api01_autenticacion.py).
    """
    auditor = client_como("cata")
    ruta = sandbox_con_incidentes / "decisions.jsonl"

    assert auditor.get("/api/v1/audit/verify").get_json()["estado"] == "ok"

    _escribir_sin_encadenar(ruta, 3)
    assert auditor.get("/api/v1/audit/verify").get_json()["estado"] == "heredado"

    lineas = ruta.read_text(encoding="utf-8").strip().split("\n")
    lineas.append(json.dumps({"n": 9, "prev_hash": "f" * 64}))
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
    assert auditor.get("/api/v1/audit/verify").get_json()["estado"] == "roto"
