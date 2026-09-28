#!/usr/bin/env python3
"""Verificador de integridad del registro de auditoría (hallazgo A-04).

Cada decisión del analista se escribe en `decisions.jsonl` con el SHA-256 del
registro anterior en su campo `prev_hash`. Eso encadena el archivo: modificar o
borrar una línea del medio invalida todos los eslabones que le siguen.

Antes de esto, "append-only e inmutable" describía una intención del diseño —
nada impedía abrir el archivo y editar una decisión. Ahora es una propiedad que
se puede comprobar, que es lo que un registro de auditoría tiene que ofrecer.

Uso:
    python3 audit_verify.py                      # decisions.jsonl y analysis_history.jsonl
    python3 audit_verify.py decisions.jsonl      # un archivo puntual
    python3 audit_verify.py --json               # salida para máquinas

Códigos de salida:  0 = cadena intacta · 1 = cadena rota · 2 = error de uso.

Esta herramienta es de **solo lectura**: no repara, no reescribe y no borra. Un
verificador que pudiera arreglar el archivo que audita no serviría de nada.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from siem_lib import read_jsonl, verificar_cadena

REGISTROS_POR_DEFECTO = ["decisions.jsonl", "analysis_history.jsonl"]


def _resumen(path: Path) -> dict:
    """Verifica un registro y agrega contexto útil para el analista."""
    resultado = verificar_cadena(path)
    resultado["archivo"] = str(path)
    resultado["existe"] = path.exists()

    if path.exists() and resultado.get("estado") in ("ok", "heredado"):
        registros = read_jsonl(path, tolerante=True)
        decisiones = [r for r in registros if r.get("decision")]
        resultado["aprobadas"] = sum(1 for r in decisiones if r["decision"] == "approved")
        resultado["descartadas"] = sum(1 for r in decisiones if r["decision"] == "dismissed")
        resultado["analistas"] = sorted({r["analyst"] for r in registros if r.get("analyst")})
        resultado["desde"] = registros[0].get("ts") if registros else None
        resultado["hasta"] = registros[-1].get("ts") if registros else None
    return resultado


def _imprimir(resultado: dict) -> None:
    archivo = resultado["archivo"]

    if not resultado["existe"]:
        print(f"  •  {archivo}: no existe todavía (sin decisiones registradas).")
        return

    if resultado.get("estado") == "heredado":
        print(f"  ⚠️  {archivo}")
        print(f"     {resultado['records']} registro(s) SIN encadenar")
        print(f"     Motivo: {resultado['reason']}")
        print()
        print("     Qué significa: estas decisiones se registraron antes de que")
        print("     existiera la cadena de hashes. NO hay indicio de manipulación:")
        print("     simplemente no se pueden verificar.")
        print("     Qué hacer: archivarlas con `./scripts/reset.sh` (que las mueve a")
        print("     audit/archive/ en vez de borrarlas). Las decisiones nuevas ya")
        print("     nacen encadenadas.")
        return

    if resultado["chain_ok"]:
        print(f"  ✅ {archivo}")
        print(f"     Cadena intacta · {resultado['records']} registro(s)")
        if resultado.get("analistas"):
            print(f"     Analistas: {', '.join(resultado['analistas'])}")
        if resultado.get("aprobadas") is not None and resultado.get("decision_total") != 0:
            print(f"     Decisiones: {resultado.get('aprobadas', 0)} aprobada(s), "
                  f"{resultado.get('descartadas', 0)} descartada(s)")
        if resultado.get("desde"):
            print(f"     Período: {resultado['desde']}  →  {resultado['hasta']}")
        return

    print(f"  ❌ {archivo}")
    print(f"     CADENA ROTA en la línea {resultado['first_broken']} "
          f"(de {resultado['records']} leída/s)")
    print(f"     Motivo: {resultado['reason']}")
    print()
    print("     Qué significa: el registro de auditoría fue modificado después de")
    print("     escribirse. Las decisiones anteriores a esa línea siguen siendo")
    print("     confiables; las posteriores no pueden verificarse.")
    print("     Qué hacer: preservar el archivo como evidencia (no lo edites ni lo")
    print("     regeneres) y escalar el hallazgo.")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verifica la integridad de los registros append-only de SIEM-IA.")
    parser.add_argument("archivos", nargs="*", default=None,
                        help=f"registros a verificar (por defecto: {', '.join(REGISTROS_POR_DEFECTO)})")
    parser.add_argument("--json", action="store_true",
                        help="salida en JSON, para CI o para otra herramienta")
    args = parser.parse_args()

    objetivos = [Path(a) for a in (args.archivos or REGISTROS_POR_DEFECTO)]
    resultados = [_resumen(p) for p in objetivos]

    if args.json:
        print(json.dumps(resultados, ensure_ascii=False, indent=2))
    else:
        print("🔍 Verificación de integridad del registro de auditoría")
        print("=" * 58)
        for resultado in resultados:
            _imprimir(resultado)
        print("=" * 58)

    # Solo una cadena ROTA es una falla. Un archivo inexistente (todavía no hubo
    # decisiones) y uno heredado (anterior al encadenado) no lo son: fallar por
    # ellos enseñaría a ignorar esta herramienta.
    roto = any(r["existe"] and r.get("estado") == "roto" for r in resultados)
    return 1 if roto else 0


if __name__ == "__main__":
    sys.exit(main())
