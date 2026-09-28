"""Lectura de las hojas de estilo, compartida por las pruebas de interfaz.

No es un archivo de pruebas: lo importan `test_contraste_de_la_interfaz.py` y
`test_tokens_de_diseno.py`, que verifican cosas distintas sobre el mismo material
—contraste WCAG una, vocabulario de tokens la otra— y necesitan el mismo parseo.

El reparto importa: `tokens.css` declara, y `app.css`, `login.css` e `iconos.css`
consumen. Cada verificación dice sobre cuál de las dos mitades opera.
"""

from __future__ import annotations

import re
from pathlib import Path

ESTATICOS = Path(__file__).resolve().parent.parent.parent / "static"

TOKENS_CSS = ESTATICOS / "tokens.css"
HOJAS_QUE_CONSUMEN = (ESTATICOS / "app.css", ESTATICOS / "login.css",
                      ESTATICOS / "iconos.css")

PLANTILLAS = ESTATICOS.parent / "templates"
SPRITE = PLANTILLAS / "_iconos.html"


def sin_comentarios(texto: str) -> str:
    """Un `/* … : … */` dentro de una regla, sin `;` que lo separe, se traga la
    declaración siguiente al partir por `;`. Lo descubrió una prueba al fallar."""
    return re.sub(r"/\*.*?\*/", "", texto, flags=re.S)


def _bloque_raiz(texto: str) -> str:
    inicio = texto.index(":root {")
    return texto[inicio:texto.index("\n}", inicio)]


# ─── Los tokens declarados ───────────────────────────────────────────────────

_RAIZ = _bloque_raiz(sin_comentarios(TOKENS_CSS.read_text(encoding="utf-8")))
_RAIZ_CON_COMENTARIOS = _bloque_raiz(TOKENS_CSS.read_text(encoding="utf-8"))

COLORES: dict[str, str] = dict(re.findall(r"--([\w-]+):\s*(#[0-9a-fA-F]{3,8})", _RAIZ))
MEDIDAS: dict[str, str] = dict(re.findall(r"--([\w-]+):\s*([\d.]+px)", _RAIZ))
ALIAS: dict[str, str] = dict(re.findall(r"--([\w-]+):\s*var\(--([\w-]+)\)", _RAIZ))
DEFINIDOS: set[str] = set(re.findall(r"--([\w-]+):", _RAIZ))


def texto_de_la_raiz() -> str:
    """El `:root` **con** sus comentarios, para verificar que esté documentado."""
    return _RAIZ_CON_COMENTARIOS


# ─── Las hojas que consumen ──────────────────────────────────────────────────

def cuerpos() -> list[tuple[Path, str]]:
    """(ruta, CSS sin comentarios) de cada hoja que consume tokens."""
    return [(h, sin_comentarios(h.read_text(encoding="utf-8"))) for h in HOJAS_QUE_CONSUMEN]


def color(valor: str) -> str | None:
    """Resuelve `#hex` o `var(--token)` —incluidos los alias— a un hex.

    Devuelve None si el valor no es un color (`inherit`, `none`, un número).
    """
    valor = valor.strip()
    for _ in range(4):  # un alias de un alias; el tope evita un ciclo
        if valor.startswith("#"):
            return valor
        m = re.fullmatch(r"var\(--([\w-]+)\)", valor)
        if not m:
            return None
        nombre = m.group(1)
        if nombre in COLORES:
            return COLORES[nombre]
        if nombre in ALIAS:
            valor = f"var(--{ALIAS[nombre]})"
            continue
        return None
    return None


def medida(valor: str) -> str:
    """Reemplaza cada `var(--token)` por su valor en px."""
    return re.sub(r"var\(--([\w-]+)\)", lambda m: MEDIDAS.get(m.group(1), m.group(0)), valor)


def declaraciones(cuerpo: str, propiedades: tuple[str, ...]) -> list[tuple[int, str, str]]:
    """(línea, propiedad, valor) de cada declaración de las propiedades pedidas.

    La línea sale del desplazamiento real: buscar el texto del match en el archivo
    devolvía siempre la primera coincidencia, así que dos reglas con el mismo
    `padding` informaban la misma línea.
    """
    return [(cuerpo.count("\n", 0, m.start()) + 1, m.group(1), m.group(2).strip())
            for m in re.finditer(rf"\b({'|'.join(propiedades)}):\s*([^;}}]+)", cuerpo)]


def regla(cuerpo: str, selector: str) -> dict[str, str]:
    """Las declaraciones de un selector, como diccionario."""
    m = re.search(re.escape(selector) + r"\s*\{([^}]*)\}", cuerpo)
    assert m, f"no encontré la regla {selector}"
    return {k.strip(): v.strip()
            for k, v in (d.split(":", 1) for d in m.group(1).split(";") if ":" in d)}
