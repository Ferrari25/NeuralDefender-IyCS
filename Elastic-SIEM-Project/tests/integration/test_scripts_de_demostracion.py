"""Los scripts de demostración en vivo (**D1** y **D2**).

`scripts/demo.sh` deja el laboratorio en un estado presentable. `scripts/demo-ataque.sh`
—el de esta tanda— lanza un ataque **mientras el público mira el panel**, para que la
detección ocurra delante de todos en lugar de estar ya en el archivo JSON.

Qué se verifica acá, y por qué:

* **`--ip` llega al evento generado.** Es lo que hace que el incidente nuevo se
  distinga de los anteriores en el panel. Si el flag se ignorara en silencio, la
  demostración seguiría "funcionando" pero quien presenta no encontraría su ataque.
* **Compatibilidad hacia atrás.** Sin `--ip`, las simulaciones tienen que generar
  exactamente lo de siempre: `docs/05` y las pruebas de clasificación dependen de
  esas IP fijas.
* **Un tipo de ataque mal escrito aborta.** Antes del bucle de argumentos, un
  `demo-ataque.sh contener` habría corrido el port scan por defecto; en vivo, eso
  es peor que un error.
* **No-autonomía.** Los scripts *generan ataques* contra el laboratorio del propio
  proyecto; ninguno ejecuta acciones de contención.

Los scripts de simulación resuelven su directorio de salida desde su propia
ubicación (`ROOT="$(dirname "$0")/.."`), así que estas pruebas **copian el árbol a
`tmp_path`** y lo corren ahí: `network_logs/` del proyecto son datos del equipo y no
se tocan.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent.parent
SIMULACION = RAIZ / "simulation"
DEMO_ATAQUE = RAIZ / "scripts" / "demo-ataque.sh"
DEMO_AUDITORIA = RAIZ / "scripts" / "demo-auditoria.sh"

SCRIPTS_DE_DEMOSTRACION = [
    RAIZ / "scripts" / "demo.sh",
    DEMO_ATAQUE,
    DEMO_AUDITORIA,
    SIMULACION / "run-port-scan.sh",
    SIMULACION / "run-phishing.sh",
    SIMULACION / "run-brute-force.sh",
]

# IP por defecto de cada simulación, fijadas en docs/05 y usadas por las pruebas de
# clasificación. `--ip` no puede cambiarlas cuando no se pasa.
IP_ESCANEO_POR_DEFECTO = "172.18.0.7"
IP_PHISHING_POR_DEFECTO = "172.18.0.8"
IP_VICTIMA_PHISHING = "172.18.0.9"


@pytest.fixture
def laboratorio(tmp_path: Path) -> Path:
    """Una copia del árbol de simulación en `tmp_path`.

    Los scripts escriben en `$ROOT/network_logs/`, donde `ROOT` sale de su propia
    ruta. Copiarlos acá es lo que mantiene intactos los datos reales del equipo.
    """
    shutil.copytree(SIMULACION, tmp_path / "simulation")
    return tmp_path


def _correr(script: Path, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["bash", str(script), *args], cwd=cwd, capture_output=True,
                          text=True, timeout=60, check=False)


def _eventos(laboratorio: Path) -> list[dict]:
    """Todo lo que quedó escrito en `network_logs/`, ya parseado."""
    return [json.loads(linea)
            for archivo in sorted((laboratorio / "network_logs").glob("*.json"))
            for linea in archivo.read_text(encoding="utf-8").splitlines() if linea.strip()]


# ─── Sintaxis ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("script", SCRIPTS_DE_DEMOSTRACION, ids=lambda p: p.name)
def test_los_scripts_de_demostracion_tienen_sintaxis_valida(script: Path):
    """Un error de sintaxis recién aparece al ejecutarlos, y eso sería en vivo."""
    r = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True, check=False)
    assert r.returncode == 0, f"{script.name}: {r.stderr}"


# ─── El contrato de argumentos de demo-ataque.sh ─────────────────────────────

def test_una_opcion_desconocida_aborta():
    r = _correr(DEMO_ATAQUE, "--borrar-todo")
    assert r.returncode == 2
    assert "Opción desconocida" in r.stdout + r.stderr


def test_un_tipo_de_ataque_mal_escrito_aborta():
    """No puede caer al tipo por defecto: en vivo, un ataque que no es el anunciado
    es peor que un mensaje de error."""
    r = _correr(DEMO_ATAQUE, "contener")
    assert r.returncode == 2, "un tipo desconocido corrió algo en vez de abortar"


def test_la_ayuda_no_lanza_ningun_ataque():
    r = _correr(DEMO_ATAQUE, "--help")
    assert r.returncode == 0
    assert "demo-ataque.sh" in r.stdout
    assert "eventos de red generados" not in r.stdout, "la ayuda ejecutó el ataque"


def test_los_tipos_documentados_son_los_que_acepta():
    """La cabecera del script es la que lee quien presenta. Si acepta un tipo que no
    documenta —o documenta uno que no acepta— alguien se entera en la proyección."""
    fuente = DEMO_ATAQUE.read_text(encoding="utf-8")

    aceptados = set(re.search(r"^\s+([a-z|-]+)\)\s+TIPO=", fuente, re.M).group(1).split("|"))
    # Un solo espacio tras el nombre del script: la línea sin argumento (que
    # describe el tipo por defecto) deja la columna alineada con varios.
    documentados = set(re.findall(r"^#\s+\./scripts/demo-ataque\.sh ([a-z-]+)\s",
                                  fuente, re.M))

    assert aceptados == documentados, (
        f"solo se aceptan: {aceptados - documentados}; solo se documentan: "
        f"{documentados - aceptados}")


def test_la_ip_que_se_genera_sola_es_del_rango_de_documentacion():
    """RFC 5737 reserva 198.51.100.0/24 para documentación: la IP que se proyecta en
    una demostración no puede ser la de un host real de alguien."""
    fuente = DEMO_ATAQUE.read_text(encoding="utf-8")
    m = re.search(r'IP_ATAQUE="(\d+\.\d+\.\d+)\.\$\(\(\s*\(RANDOM % (\d+)\) \+ (\d+)\s*\)\)"',
                  fuente)
    assert m, "cambió la generación de IP; revisar que siga en el rango reservado"

    red, modulo, base = m.group(1), int(m.group(2)), int(m.group(3))
    assert red == "198.51.100", "fuera del rango de documentación de RFC 5737"
    assert base + modulo - 1 <= 254, "el último octeto puede desbordar a broadcast"
    assert base >= 1


# ─── `--ip` llega al evento (D2) ─────────────────────────────────────────────

def test_el_escaneo_usa_la_ip_indicada(laboratorio: Path):
    r = _correr(laboratorio / "simulation" / "run-port-scan.sh", "--offline",
                "--ip", "198.51.100.77")
    assert r.returncode == 0, r.stderr

    origenes = {e["source_ip"] for e in _eventos(laboratorio)}
    assert origenes == {"198.51.100.77"}, "el flag --ip no llegó a los eventos"


def test_el_escaneo_sin_ip_mantiene_la_de_siempre(laboratorio: Path):
    """Compatibilidad hacia atrás: `docs/05` y las pruebas de clasificación la fijan."""
    assert _correr(laboratorio / "simulation" / "run-port-scan.sh", "--offline").returncode == 0
    assert {e["source_ip"] for e in _eventos(laboratorio)} == {IP_ESCANEO_POR_DEFECTO}


def test_el_escaneo_genera_un_evento_por_puerto(laboratorio: Path):
    _correr(laboratorio / "simulation" / "run-port-scan.sh", "--offline")
    eventos = _eventos(laboratorio)

    assert len(eventos) == 26
    assert len({e["dest_port"] for e in eventos}) == 26, "hay puertos repetidos"
    assert all(e["event_type"] == "network_flow" for e in eventos)


def test_el_phishing_usa_la_ip_indicada_como_servidor_falso(laboratorio: Path):
    """En phishing, `--ip` es el **servidor de la página falsa** (el destino). El
    origen sigue siendo la víctima que envía sus credenciales.

    Esta asimetría es la que motivó el arreglo del listado en `demo-ataque.sh`:
    mostrar `source_ip` en un incidente de phishing muestra a la víctima, y quien
    presenta busca en el panel la IP del ataque que acaba de lanzar.
    """
    r = _correr(laboratorio / "simulation" / "run-phishing.sh", "--offline",
                "--ip", "198.51.100.77")
    assert r.returncode == 0, r.stderr

    eventos = _eventos(laboratorio)
    assert {e["dest_ip"] for e in eventos} == {"198.51.100.77"}, "la página falsa"
    assert {e["source_ip"] for e in eventos} == {IP_VICTIMA_PHISHING}, "la víctima"


def test_el_phishing_sin_ip_mantiene_la_de_siempre(laboratorio: Path):
    assert _correr(laboratorio / "simulation" / "run-phishing.sh", "--offline").returncode == 0
    assert {e["dest_ip"] for e in _eventos(laboratorio)} == {IP_PHISHING_POR_DEFECTO}


def test_el_phishing_emite_la_visita_y_el_envio_de_credenciales(laboratorio: Path):
    _correr(laboratorio / "simulation" / "run-phishing.sh", "--offline")
    eventos = _eventos(laboratorio)

    assert [e["http_method"] for e in eventos] == ["GET", "POST"]
    assert [e["credential_submission"] for e in eventos] == [False, True]


@pytest.mark.parametrize("script", ["run-port-scan.sh", "run-phishing.sh"])
def test_las_simulaciones_rechazan_opciones_desconocidas(laboratorio: Path, script: str):
    r = _correr(laboratorio / "simulation" / script, "--offline", "--borrar")

    assert r.returncode == 2
    assert not (laboratorio / "network_logs").exists(), (
        "abortó pero igual generó eventos: el bucle de argumentos corre antes de escribir")


@pytest.mark.parametrize("script", ["run-port-scan.sh", "run-phishing.sh"])
def test_una_corrida_nueva_no_pisa_los_eventos_de_la_anterior(laboratorio: Path, script: str):
    """Filebeat (`filestream`) identifica archivos por inode: truncar y reescribir le
    desincroniza el offset y la corrida siguiente no se ingiere.

    El nombre lleva marca de tiempo en segundos, así que dos corridas del mismo tipo
    dentro del mismo segundo comparten archivo — pero lo abren con `>>`. Lo que se
    verifica es la garantía real: **ningún evento se pierde**. Un archivo nuevo por
    corrida es el mecanismo habitual, no la propiedad.
    """
    ruta = laboratorio / "simulation" / script
    assert _correr(ruta, "--offline").returncode == 0
    de_la_primera = len(_eventos(laboratorio))

    assert _correr(ruta, "--offline", "--ip", "198.51.100.77").returncode == 0
    eventos = _eventos(laboratorio)

    assert len(eventos) == de_la_primera * 2, "la segunda corrida truncó a la primera"
    campo = "source_ip" if "port-scan" in script else "dest_ip"
    assert "198.51.100.77" in {e[campo] for e in eventos}, "falta la segunda corrida"
    assert len({e[campo] for e in eventos}) == 2, "falta la primera corrida"


def test_los_eventos_generados_son_ndjson_valido(laboratorio: Path):
    """El clasificador los lee línea por línea; una línea rota descarta el archivo."""
    _correr(laboratorio / "simulation" / "run-port-scan.sh", "--offline")
    _correr(laboratorio / "simulation" / "run-phishing.sh", "--offline")

    archivos = list((laboratorio / "network_logs").glob("*.json"))
    assert len(archivos) == 2

    for archivo in archivos:
        lineas = [ln for ln in archivo.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert lineas, f"{archivo.name} quedó vacío"
        for linea in lineas:
            json.loads(linea)  # revienta acá si no es JSON válido


# ─── El listado del panel muestra al atacante (D2) ───────────────────────────

def test_el_listado_muestra_al_atacante_y_no_al_origen():
    """En phishing, `source_ip` es la víctima. Quien presenta busca la IP que lanzó
    el ataque, así que el listado tiene que mostrar `attacker_ips`."""
    fuente = DEMO_ATAQUE.read_text(encoding="utf-8")
    assert "attacker_ips" in fuente, (
        "el listado volvió a mostrar source_ip: en phishing eso es la víctima")


def test_el_listado_muestra_el_identificador_de_campana():
    """Sin la columna 🔗 no se ve la correlación, que es lo que el modo `campana`
    existe para demostrar."""
    assert "campaign_id" in DEMO_ATAQUE.read_text(encoding="utf-8")


# ─── No-autonomía ────────────────────────────────────────────────────────────

# Verbos de contención sobre infraestructura. `ssh` se busca como comando seguido de
# un destino: el nombre de contenedor `ssh-target` no lo activa.
CONTENCION = [
    r"\bufw\b", r"\biptables\b", r"\bnft\b", r"\bfail2ban-client\b", r"\bsystemctl\b",
    r"\bpkill\b", r"\bkill\s+-", r"\bshutdown\b", r"\breboot\b", r"\busermod\b",
    r"\bip\s+route\b", r"\btc\s+qdisc\b", r"\bssh\s+[\w.@]",
]


@pytest.mark.parametrize("script", SCRIPTS_DE_DEMOSTRACION, ids=lambda p: p.name)
def test_ningun_script_de_demostracion_ejecuta_acciones_de_contencion(script: Path):
    """Estos scripts **generan ataques** contra el laboratorio del propio proyecto.
    Ninguno bloquea, aísla ni apaga nada: el sistema detecta y sugiere, y quien
    contiene es una persona, fuera del sistema."""
    fuente = script.read_text(encoding="utf-8")
    encontrados = [p for p in CONTENCION if re.search(p, fuente)]

    assert not encontrados, (
        f"{script.name} ejecuta contención: {encontrados}. Ver docs/10 §6 — esto "
        f"rompe el principio rector y no se silencia, se revierte.")


# ─── El guion de demo.sh no ejecuta nada al imprimirse ───────────────────────

def _cuerpo_del_guion() -> str:
    """El texto entre `cat <<GUION` y su delimitador de cierre."""
    fuente = (RAIZ / "scripts" / "demo.sh").read_text(encoding="utf-8")
    m = re.search(r"^\s*cat <<GUION$(.*?)^GUION$", fuente, re.M | re.S)
    assert m, "cambió la forma del heredoc del guion"
    return m.group(1)


def test_el_guion_no_contiene_sustituciones_de_comandos():
    """El heredoc es `cat <<GUION` **sin comillas**, a propósito: expande
    `$USUARIO_DEMO` y `$PASSWORD_DEMO` para que quien presenta lea las credenciales
    reales del laboratorio.

    El precio es que backticks y `$(...)` dentro del guion se **ejecutan**. Escribir
    prosa con backticks es lo natural —es la sintaxis de código en Markdown— y el
    resultado es silencioso: el texto desaparece y el guion sigue imprimiéndose.
    Pasó al redactar el paso 7 de D2: `` `campana` `` salió como una línea vacía.
    """
    cuerpo = _cuerpo_del_guion()

    assert "`" not in cuerpo, (
        "hay backticks en el guion: bash los ejecuta y el texto sale vacío. "
        "Escribir el término sin comillas invertidas.")
    assert "$(" not in cuerpo, "hay una sustitución de comandos en el guion"


def test_el_guion_solo_expande_las_variables_previstas():
    variables = set(re.findall(r"\$([A-Z_][A-Z0-9_]*)", _cuerpo_del_guion()))
    assert variables <= {"USUARIO_DEMO", "PASSWORD_DEMO", "USUARIO_VIEWER",
                         "PASSWORD_VIEWER", "USUARIO_AUDITOR", "PASSWORD_AUDITOR"}, (
        f"variable inesperada en el guion: {variables}")


def test_el_guion_manda_al_script_de_ataque_en_vivo():
    """El paso 7 mandaba a `run-port-scan.sh --offline`, que usa la IP fija
    172.18.0.7 — la misma que `demo.sh` ya usó al preparar el laboratorio. El
    incidente "en vivo" se habría fundido con el que ya estaba en el panel, sin nada
    nuevo que señalar. Ese es justamente el problema que D2 resolvió."""
    cuerpo = _cuerpo_del_guion()

    assert "./scripts/demo-ataque.sh" in cuerpo
    assert "run-port-scan.sh --offline && python3 siem_pipeline.py" not in cuerpo, (
        "el guion volvió a los comandos a mano, con IP fija")


# ─── La ruptura de la cadena de auditoría (D3) ───────────────────────────────

@pytest.fixture
def laboratorio_auditoria(tmp_path: Path) -> Path:
    """Un árbol mínimo con un `decisions.jsonl` encadenado de juguete.

    `demo-auditoria.sh` resuelve su raíz desde su propia ubicación, así que corre
    contra el registro que encuentra ahí. En `tmp_path` eso es un archivo de prueba,
    nunca el del equipo.
    """
    import siem_lib

    (tmp_path / "scripts").mkdir()
    shutil.copy(DEMO_AUDITORIA, tmp_path / "scripts" / DEMO_AUDITORIA.name)
    for modulo in ("audit_verify.py", "siem_lib.py", "siem_validators.py", ".devtools"):
        (tmp_path / modulo).symlink_to(RAIZ / modulo)

    registro = tmp_path / "decisions.jsonl"
    for n in range(1, 4):
        siem_lib.append_jsonl(registro, {
            "ts": f"2026-09-0{n}T10:00:00+00:00", "incident_id": f"INC-T-{n}",
            "action_id": f"INC-T-{n}-a1", "decision": "approved",
            "analyst": "prueba", "source_ip": "198.51.100.5"})
    return tmp_path


def _demostrar_ruptura(laboratorio: Path) -> dict:
    r = _correr(laboratorio / "scripts" / "demo-auditoria.sh", "--json", cwd=laboratorio)
    assert r.returncode == 0, f"la demostración falló:\n{r.stdout}\n{r.stderr}"
    return json.loads(r.stdout)


def test_la_ruptura_de_la_cadena_se_detecta(laboratorio_auditoria: Path):
    """Lo que la demostración afirma delante del tribunal, verificado."""
    resultado = _demostrar_ruptura(laboratorio_auditoria)

    assert resultado["antes"]["estado"] == "ok"
    assert resultado["antes"]["chain_ok"] is True
    assert resultado["despues"]["estado"] == "roto", (
        "se alteró una decisión y el verificador NO lo detectó: la demostración "
        "mostraría lo contrario de lo que dice")
    assert resultado["despues"]["chain_ok"] is False
    assert resultado["despues"]["first_broken"] is not None, "no señaló la línea"


def test_la_demostracion_no_modifica_el_registro(laboratorio_auditoria: Path):
    """La propiedad que hace que este script se pueda correr sin miedo."""
    registro = laboratorio_auditoria / "decisions.jsonl"
    antes = registro.read_bytes()

    _demostrar_ruptura(laboratorio_auditoria)

    assert registro.read_bytes() == antes, (
        "el script modificó el registro. En el proyecto real eso serían los datos "
        "del equipo.")


def test_la_salida_json_no_tiene_ruido(laboratorio_auditoria: Path):
    """`--json` se puede encadenar con otra herramienta: si la narración se filtra,
    `json.loads` falla. Ya pasó una vez con el detalle del paso 2."""
    r = _correr(laboratorio_auditoria / "scripts" / "demo-auditoria.sh", "--json",
                cwd=laboratorio_auditoria)
    json.loads(r.stdout)  # revienta acá si se colaron líneas narradas


def test_sin_registro_avisa_que_hay_que_decidir_primero(tmp_path: Path):
    (tmp_path / "scripts").mkdir()
    shutil.copy(DEMO_AUDITORIA, tmp_path / "scripts" / DEMO_AUDITORIA.name)

    r = _correr(tmp_path / "scripts" / "demo-auditoria.sh", "--rapido", cwd=tmp_path)

    assert r.returncode == 1
    assert "demo.sh" in r.stdout, "el mensaje tiene que decir cómo salir del paso"


def test_la_demostracion_de_auditoria_rechaza_opciones_desconocidas():
    r = _correr(DEMO_AUDITORIA, "--romper-de-verdad")
    assert r.returncode == 2


def test_alterar_el_ultimo_registro_no_es_detectable(tmp_path: Path):
    """**Por qué `demo-auditoria.sh` agrega registros antes de alterar uno.**

    Un encadenado protege cada registro a través del **siguiente**: el último eslabón
    queda expuesto hasta que otro lo cubre. Alterar el último registro de un
    `decisions.jsonl` no rompe nada, porque no hay ningún `prev_hash` que lo apunte.

    Es una propiedad real del mecanismo, no un defecto, y conviene poder enunciarla
    si la preguntan en la defensa. Si alguien "simplifica" el script quitando la
    siembra, la demostración mostraría la cadena intacta después de alterarla —
    exactamente lo contrario de lo que afirma.
    """
    import siem_lib

    registro = tmp_path / "decisions.jsonl"
    for n in (1, 2):
        siem_lib.append_jsonl(registro, {"ts": f"2026-09-0{n}T10:00:00+00:00",
                                         "decision": "approved", "analyst": "prueba"})

    lineas = registro.read_text(encoding="utf-8").splitlines()
    ultimo = json.loads(lineas[-1])
    ultimo["decision"] = "dismissed"
    lineas[-1] = json.dumps(ultimo, ensure_ascii=False)
    registro.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(registro)["chain_ok"] is True, (
        "si esto empieza a fallar, el encadenado protege también el último registro "
        "(p. ej. por un ancla externa) y demo-auditoria.sh puede dejar de sembrar")

    # Y el registro ANTERIOR sí está protegido, que es lo que el script explota.
    lineas = registro.read_text(encoding="utf-8").splitlines()
    primero = json.loads(lineas[0])
    primero["decision"] = "dismissed"
    lineas[0] = json.dumps(primero, ensure_ascii=False)
    registro.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    assert siem_lib.verificar_cadena(registro)["chain_ok"] is False


# ─── El guion no puede mandar a un script que no existe ─────────────────────

def test_todos_los_scripts_que_nombra_el_guion_existen():
    """El paso 8 apuntó a `./scripts/demo-auditoria.sh` antes de que existiera. Un
    guion que manda a un archivo inexistente falla en la proyección."""
    nombrados = set(re.findall(r"\./scripts/([\w-]+\.sh)", _cuerpo_del_guion()))
    assert nombrados, "el guion dejó de nombrar scripts; revisar la expresión"

    faltan = [n for n in nombrados if not (RAIZ / "scripts" / n).exists()]
    assert not faltan, f"el guion manda a scripts que no existen: {faltan}"
