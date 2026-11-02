# Pruebas de interfaz

Las pruebas de `tests/unit/` y `tests/integration/` verifican funciones y APIs:
lo que el servidor **responde**. Las de `tests/interfaz/` verifican lo que el
analista **ve y hace**: un navegador real (Chromium, manejado por
[Playwright](https://playwright.dev/python/)) abre el panel, tipea, hace clic y
lee la pantalla. Son las únicas que ejecutan `static/app.js` y `static/login.js`.

## Cómo funcionan

1. **El panel se sirve de verdad.** La fixture `panel` (`tests/interfaz/conftest.py`)
   toma el mismo `dashboard` que usa el resto de la suite —sandbox temporal,
   usuarios de prueba `ana` (analyst), `beto` (viewer) y `cata` (auditor), malla de
   microservicios en proceso— y lo levanta con un servidor HTTP real en un puerto
   efímero de `127.0.0.1`, en un hilo. **CSRF queda encendido**, como en producción.
2. **Chromium lo usa como una persona.** `pytest-playwright` provee la fixture `page`
   (una pestaña nueva y limpia por prueba). La fixture `entrar("ana")` completa el
   login y espera a que se dibuje la tabla de incidentes.
3. **Se afirma sobre la pantalla y sobre el registro.** `expect(...)` de Playwright
   reintenta solo hasta 5 s, así que no hace falta poner esperas a mano. Las pruebas
   de decisiones además leen `data/decisions.jsonl` del sandbox para comprobar que
   lo que se vio en pantalla quedó registrado (y que cancelar no registra nada).
4. **Nunca tocan los datos reales** ni el panel que está corriendo en Docker.

## Qué prueba cada caso (`tests/interfaz/test_panel.py`)

| Prueba | Qué verifica |
|--------|--------------|
| `test_sin_sesion_el_panel_manda_al_login` | Sin sesión, `/` redirige a `/login`. |
| `test_contrasena_incorrecta_muestra_el_error_y_vacia_el_campo` | Mensaje de error visible, contraseña borrada, sigue en `/login`. |
| `test_login_correcto_muestra_usuario_rol_e_incidentes` | Usuario y rol arriba, tabla con incidentes, **cero errores de JavaScript** en consola. |
| `test_cerrar_sesion_vuelve_al_login_y_corta_el_acceso` | «Salir» vuelve al login y `/` ya no deja entrar. |
| `test_el_buscador_filtra_la_tabla` | El buscador vacía y restaura la tabla. |
| `test_clic_en_una_fila_abre_el_detalle_con_sus_acciones` | El detalle muestra el incidente, sus acciones y de dónde salió el análisis. |
| `test_una_fila_se_abre_con_el_teclado` | Accesibilidad (RNF-USA-08): foco + Enter abre el detalle. |
| `test_cancelar_la_confirmacion_no_registra_nada` | «Aprobar» abre el cuadro de confirmación; «Cancelar» no deja rastro. |
| `test_aprobar_con_confirmacion_queda_en_pantalla_y_en_el_registro` | Confirmar marca la acción aprobada y escribe una decisión firmada por `ana`. |
| `test_descartar_pide_motivo_y_lo_guarda` | Descartar pide motivo, confirma, y el motivo queda como `note`. |
| `test_un_viewer_no_ve_los_botones_de_decision` | Un viewer ve el detalle pero no los botones Aprobar/Descartar. |
| `test_un_analisis_de_gemma_se_identifica_en_pantalla` | Insignia «IA (Gemma local)», modelo usado y preguntas de investigación. |
| `test_un_texto_hostil_del_llm_se_muestra_como_texto_y_no_se_ejecuta` | XSS (S-02) desde el navegador: el HTML del análisis se ve como texto y no corre. |

Se verificó que detectan defectos: quitando la confirmación de `aprobarAccion` y
des-escapando el HTML en `pintar()`, fallan las 3 pruebas que corresponden.

## Instalación (una sola vez)

```bash
cd Elastic-SIEM-Project
python3 -m pip install --upgrade --target=.devtools -r requirements.txt -r requirements-dev.txt
PYTHONPATH=.devtools python3 -m playwright install chromium   # ~120 MB en ~/.cache/ms-playwright
```

Sin Playwright o sin Chromium, las pruebas de interfaz **se saltean** (no fallan),
así la suite sigue corriendo en un equipo que no los tenga.

## Cómo correrlas

```bash
export PYTHONPATH="$PWD/.devtools"
.devtools/bin/pytest tests/interfaz                      # ~13 s, sin ventana (headless)
.devtools/bin/pytest tests/interfaz --headed --slowmo 400  # VER el navegador haciendo cada paso
.devtools/bin/pytest tests/interfaz -k aprobar           # una sola
.devtools/bin/pytest tests/interfaz --tracing retain-on-failure  # si falla, deja una traza
PYTHONPATH=.devtools python3 -m playwright show-trace test-results/*/trace.zip  # y se mira paso a paso
```

También corren dentro de `./scripts/pruebas_de_servicio.sh` (etapa **INTERFAZ**) y,
por lo tanto, de `./scripts/pruebas_completas.sh`.

## Agregar una prueba

```python
def test_algo_nuevo(entrar, sandbox_con_incidentes):
    page = entrar("ana")                       # o "beto" (viewer), "cata" (auditor)
    page.locator("table.events tbody tr").first.click()
    expect(page.locator("#detailWrap")).to_contain_text("…")
```

Preferir selectores estables (`#id`, `data-accion`, `data-incidente`) antes que
textos que pueden cambiar de redacción.
