"""Regresión del hallazgo **A-01** — `reset.sh` destruía el registro de auditoría.

`decisions.jsonl` se describe en cinco documentos del proyecto como "registro
inmutable" y "append-only", y es el único artefacto que prueba que hubo
supervisión humana sobre cada acción sugerida. Sin embargo,
`scripts/reset.sh --yes` lo borraba en el mismo `rm` que los datos de demo, sin
ninguna confirmación específica.

Un registro que un script del propio repositorio elimina junto a archivos
regenerables no es un registro de auditoría: es un archivo de trabajo.

**Estas pruebas ejecutan el `reset.sh` real** en un sandbox, con un `docker` de
juguete al frente del PATH que registra su invocación y sale con 0. Así el
script recorre su camino completo sin tocar ni un contenedor del sistema.
Probarlo leyendo su texto diría poco: lo que importa es qué archivos quedan en
el disco después de correrlo.

Reemplazan al congelado `test_A01_reset_sh_borra_el_registro_de_auditoria`.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
RESET = PROJECT_ROOT / "scripts" / "reset.sh"

DECISION = ('{"ts":"2026-09-16T10:00:00+00:00","incident_id":"INC-AUTH-1",'
            '"action_id":"INC-AUTH-1-a1","decision":"approved","analyst":"ana",'
            '"note":"confirmado","source_ip":"203.0.113.7","attacker_ips":[]}\n')
CORRIDA = '{"ts":"2026-09-16T10:00:00+00:00","analyst_mode":"fallback","incident_count":1}\n'


@pytest.fixture
def docker_falso(tmp_path):
    """Un `docker` de juguete que sale con 0 y anota lo que le pidieron.

    Sin esto, `docker compose down` falla ("no configuration file provided"), y
    como el script corre con `set -e` abortaría antes de llegar al archivado —
    el test pasaría por el motivo equivocado.
    """
    bin_dir = tmp_path / "bin_falso"
    bin_dir.mkdir()
    stub = bin_dir / "docker"
    stub.write_text('#!/bin/bash\necho "$@" >> "$(dirname "$0")/llamadas.txt"\nexit 0\n',
                    encoding="utf-8")
    stub.chmod(0o755)
    return bin_dir


@pytest.fixture
def proyecto_falso(tmp_path, docker_falso):
    """Copia mínima del proyecto con auditoría y artefactos regenerables."""
    del docker_falso  # lo consume _correr_reset vía tmp_path
    (tmp_path / "scripts").mkdir()
    shutil.copy(RESET, tmp_path / "scripts" / "reset.sh")
    (tmp_path / "scripts" / "reset.sh").chmod(0o755)
    (tmp_path / "network_logs").mkdir()

    # Auditoría (no se puede perder).
    (tmp_path / "decisions.jsonl").write_text(DECISION, encoding="utf-8")
    (tmp_path / "analysis_history.jsonl").write_text(CORRIDA, encoding="utf-8")
    # Artefactos regenerables (sí se borran).
    (tmp_path / "siem_clean.json").write_text("{}", encoding="utf-8")
    (tmp_path / "siem_incidents.json").write_text("{}", encoding="utf-8")
    (tmp_path / "ai_report.json").write_text("{}", encoding="utf-8")
    (tmp_path / "network_logs" / "port-scan-1.json").write_text("{}", encoding="utf-8")
    return tmp_path


def _correr_reset(directorio: Path, *args: str, entrada: str = "") -> subprocess.CompletedProcess:
    """Ejecuta el reset.sh real con un `docker` de juguete al frente del PATH."""
    bin_falso = directorio / "bin_falso"
    entorno = {**os.environ, "PATH": f"{bin_falso}:/usr/bin:/bin"}
    return subprocess.run(
        ["bash", "scripts/reset.sh", *args],
        cwd=directorio, input=entrada, capture_output=True, text=True,
        timeout=60, env=entorno, check=False,
    )


def _auditoria_archivada(directorio: Path) -> list[Path]:
    archivo = directorio / "audit" / "archive"
    return sorted(archivo.rglob("*.jsonl")) if archivo.exists() else []


# ─── El comportamiento corregido ─────────────────────────────────────────────

def test_el_reset_no_borra_la_auditoria(proyecto_falso):
    """Lo esencial: después del reset, las decisiones siguen existiendo."""
    _correr_reset(proyecto_falso, "--yes")

    archivados = _auditoria_archivada(proyecto_falso)
    nombres = {p.name for p in archivados}
    assert nombres == {"decisions.jsonl", "analysis_history.jsonl"}


def test_el_contenido_archivado_es_identico(proyecto_falso):
    """Archivar no puede alterar ni un byte: es evidencia."""
    _correr_reset(proyecto_falso, "--yes")

    decisiones = next(p for p in _auditoria_archivada(proyecto_falso)
                      if p.name == "decisions.jsonl")
    assert decisiones.read_text(encoding="utf-8") == DECISION


def test_el_archivo_queda_de_solo_lectura(proyecto_falso):
    """Una vez archivada, la auditoría no se edita ni por accidente."""
    _correr_reset(proyecto_falso, "--yes")

    for archivado in _auditoria_archivada(proyecto_falso):
        modo = archivado.stat().st_mode & 0o222
        assert modo == 0, f"{archivado.name} quedó con permiso de escritura"


def test_los_artefactos_regenerables_si_se_borran(proyecto_falso):
    """El reset tiene que seguir haciendo su trabajo: dejar el sistema en cero."""
    _correr_reset(proyecto_falso, "--yes")

    for regenerable in ("siem_clean.json", "siem_incidents.json", "ai_report.json"):
        assert not (proyecto_falso / regenerable).exists(), f"{regenerable} sobrevivió"
    assert list((proyecto_falso / "network_logs").glob("*.json")) == []


def test_el_dashboard_arranca_vacio_tras_el_reset(proyecto_falso):
    """El objetivo original del script se mantiene: panel en cero."""
    _correr_reset(proyecto_falso, "--yes")
    assert not (proyecto_falso / "siem_incidents.json").exists()
    assert not (proyecto_falso / "decisions.jsonl").exists(), \
        "se movió al archivo, no quedó en su lugar original"


def test_sin_auditoria_previa_no_falla(tmp_path, docker_falso):
    """Un reset en un proyecto recién clonado no tiene nada que archivar."""
    del docker_falso
    (tmp_path / "scripts").mkdir()
    shutil.copy(RESET, tmp_path / "scripts" / "reset.sh")
    (tmp_path / "network_logs").mkdir()

    resultado = _correr_reset(tmp_path, "--yes")
    assert "No había auditoría que archivar" in resultado.stdout
    assert not (tmp_path / "audit").exists()


def test_dos_resets_seguidos_no_se_pisan(proyecto_falso):
    """Cada reset archiva en su propio directorio con timestamp."""
    _correr_reset(proyecto_falso, "--yes")
    (proyecto_falso / "decisions.jsonl").write_text(DECISION, encoding="utf-8")
    _correr_reset(proyecto_falso, "--yes")

    directorios = sorted((proyecto_falso / "audit" / "archive").iterdir())
    assert len(directorios) == 2, "el segundo reset pisó el archivo del primero"


# ─── El borrado explícito, que sí existe pero cuesta ─────────────────────────

def test_wipe_audit_exige_una_confirmacion_escrita(proyecto_falso):
    """Borrar la auditoría es posible, pero nunca por accidente."""
    _correr_reset(proyecto_falso, "--yes")
    assert _auditoria_archivada(proyecto_falso)

    # Confirmación incorrecta: no se borra nada.
    resultado = _correr_reset(proyecto_falso, "--yes", "--wipe-audit", entrada="y\n")
    assert "Cancelado" in resultado.stdout
    assert _auditoria_archivada(proyecto_falso)


def test_wipe_audit_con_la_frase_exacta_si_borra(proyecto_falso):
    """Con la frase completa se borra: es una decisión, no un descuido."""
    _correr_reset(proyecto_falso, "--yes")
    assert _auditoria_archivada(proyecto_falso)

    resultado = _correr_reset(proyecto_falso, "--yes", "--wipe-audit",
                              entrada="BORRAR AUDITORIA\n")
    assert "Auditoría archivada eliminada" in resultado.stdout
    assert not (proyecto_falso / "audit" / "archive").exists()


def test_una_opcion_desconocida_aborta(proyecto_falso):
    """Un typo como `--wipe_audit` no puede interpretarse como otra cosa."""
    resultado = _correr_reset(proyecto_falso, "--wipe_audit")
    assert resultado.returncode == 2
    assert (proyecto_falso / "decisions.jsonl").exists()


# ─── La garantía, dicha como invariante ──────────────────────────────────────

def test_ningun_rm_del_script_menciona_la_auditoria():
    """Verificación estática, complementaria a las de comportamiento.

    Si alguien vuelve a agregar `decisions.jsonl` a un `rm`, esto lo detecta
    aunque el flujo de archivado siga existiendo en paralelo.
    """
    for linea in RESET.read_text(encoding="utf-8").splitlines():
        limpia = linea.strip()
        if limpia.startswith("rm ") and "audit/archive" not in limpia:
            assert "decisions.jsonl" not in limpia
            assert "analysis_history.jsonl" not in limpia


def test_si_docker_falla_no_se_toca_nada(proyecto_falso):
    """`set -e` aborta antes del archivado, y eso es lo correcto.

    Un reset a medias no puede dejar la auditoría en un estado intermedio: si el
    apagado de contenedores falla, los archivos quedan donde estaban.
    """
    stub = proyecto_falso / "bin_falso" / "docker"
    stub.write_text("#!/bin/bash\nexit 1\n", encoding="utf-8")
    stub.chmod(0o755)

    resultado = _correr_reset(proyecto_falso, "--yes")
    assert resultado.returncode != 0
    assert (proyecto_falso / "decisions.jsonl").read_text(encoding="utf-8") == DECISION
    assert (proyecto_falso / "siem_clean.json").exists()
