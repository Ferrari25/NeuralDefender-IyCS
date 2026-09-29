# 03 · Autenticación, sesiones y control de acceso

> Índice completo de `docs/` en [00 · Contexto, arquitectura y requerimientos](00-arquitectura.md).

## El problema que resuelve

Antes de tener autenticación, el campo `analyst` del registro inmutable salía
de una variable de entorno (`ANALYST_NAME`): quien corría el proceso decidía
qué nombre quedaba firmando cada decisión. La cadena de hash del registro
garantiza que no se alteró **después** de escribirse; no garantizaba **quién**
lo escribió. Para un sistema cuya premisa entera es *la IA sugiere, el humano
decide y todo queda trazado*, esa era la brecha más importante.

Ahora cada decisión queda firmada con la identidad real de la sesión:

```json
{
  "ts": "2026-09-17T17:30:57+00:00",
  "analyst": "ana", "analyst_rol": "analyst",
  "session_id": "12b1217a80fef1f6", "user_agent": "Mozilla/5.0 …",
  "decision": "approved", "prev_hash": "a3f2…"
}
```

## Nota de diseño que conviene leer primero

> **Ningún rol puede ejecutar acciones de contención.** El control de acceso
> decide **quién decide**, no quién ejecuta — porque nadie ejecuta, nunca. No
> existe un rol `admin` que "apriete el botón rojo": ese botón no existe en
> el sistema. La ejecución la hace una persona, a mano, fuera de la
> plataforma.

Agregar autenticación **no agregó capacidad de actuar**: agregó identidad a
quien decide. La no-autonomía sigue certificada por `tests/test_no_autonomy.py`
(recorre el AST de todo el código), reforzada del lado del RBAC por pruebas
dedicadas que verifican que ningún permiso declare capacidad de ejecución.

## Roles y permisos

Los permisos viven en **una tabla** (`siem_auth.PERMISOS`), no dispersos en
`if` por las vistas — una fila de más es mucho más fácil de auditar que un
permiso mal puesto dentro de una función.

| Rol | Ver triage | Ver auditoría | Decidir | Verificar cadena |
|-----|:----------:|:-------------:|:-------:|:----------------:|
| `viewer` | ✅ | ✅ | ❌ | ❌ |
| `analyst` | ✅ | ✅ | ✅ | ❌ |
| `auditor` | ✅ | ✅ | ❌ | ✅ |

**Por qué el analista no verifica la cadena.** Separación de funciones: quien
decide no debería ser quien certifica que el registro de sus decisiones está
intacto — mismo principio por el que nadie audita su propio trabajo.

Las vistas exigen **un permiso**, no un rol:

```python
@app.route("/api/v1/decision", methods=["POST"])
@requiere_permiso("decidir")
def api_decision(): ...
```

Pedir el permiso y no el rol es lo que permite cambiar la tabla sin tocar una
sola vista — si esto exigiera `rol == "analyst"`, agregar un rol nuevo
obligaría a recorrer todos los endpoints.

## Cómo se usa

```bash
# 1. Clave de firma de la cookie. SIN ESTO EL PANEL NO ARRANCA.
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
#   → agregar a .env como SECRET_KEY=<valor>

# 2. Crear el primer usuario
export PYTHONPATH="$PWD/.devtools"
python3 src/manage_users.py crear ana --rol analyst

# 3. Arrancar
python3 src/dashboard.py     # → http://127.0.0.1:5000/login
```

Gestión de usuarios:

```bash
python3 src/manage_users.py roles                    # qué puede cada rol
python3 src/manage_users.py listar -v                # usuarios y permisos
python3 src/manage_users.py crear beto --rol viewer
python3 src/manage_users.py password ana             # cambiar contraseña
python3 src/manage_users.py rol ana --rol auditor    # cambiar rol
python3 src/manage_users.py baja ana                 # desactivar (no borra)
python3 src/manage_users.py alta ana                 # reactivar
```

**La baja no borra** — borrar un usuario dejaría decisiones firmadas por
alguien que ya no existe, y el registro es inmutable. **La baja tiene efecto
inmediato** — el almacén se relee en cada petición, así que la sesión
abierta de un usuario dado de baja deja de valer en la siguiente petición.

## Decisiones técnicas y por qué

| Decisión | Elección | Por qué |
|----------|----------|---------|
| Hash de contraseña | **Argon2id** (`argon2-cffi`, RFC 9106) | Estándar recomendado actual; los parámetros van versionados en el hash, así que se puede endurecer sin migrar nada |
| Rehash automático | Al iniciar sesión, si los parámetros quedaron viejos | Es el único momento en que la contraseña está disponible en claro |
| Almacén | `users.json`, `0600`, gestionado por CLI | Sin base de datos: cero dependencias de infraestructura adicionales |
| Alta de usuarios | Por línea de comandos, no por la web | Crear cuentas es administración del sistema; exponerlo en la web agrega superficie de ataque para ganar comodidad en algo puntual |
| Sesión | `Flask-Login` + cookie firmada | `SECRET_KEY` desde `.env`; el servidor **no arranca** si falta |
| Flags de cookie | `HttpOnly`, `SameSite=Lax`, `Secure` con TLS | `HttpOnly` la hace inaccesible desde JavaScript; `Lax` impide que viaje en un POST de otro sitio |
| CSRF | `Flask-WTF`, token por header `X-CSRFToken` | La API es JSON, así que el token va por header y no por formulario |
| Expiración | 30 min de inactividad · 8 h absoluta | El de inactividad protege una terminal desatendida; el absoluto acota el daño de una cookie robada |
| Anti-fuerza bruta | 5 intentos / 15 min por usuario+IP, con backoff | Irónico que un sistema que detecta fuerza bruta sea vulnerable a ella |
| IP del cliente | `remote_addr`, **nunca** `X-Forwarded-For` | El encabezado lo pone el cliente: usarlo permitiría esquivar el bloqueo cambiándolo |
| `session_id` en el registro | Resumen derivado, no la cookie | Guardar el identificador real en un archivo append-only dejaría un token válido a la vista de quien lea la auditoría |

**Por qué `SECRET_KEY` no tiene valor por defecto.** Un default haría que
todos los despliegues firmaran sus cookies con la misma clave — cualquiera
que conozca el repositorio podría fabricar una sesión válida. Preferimos que
el servidor **no arranque** a que arranque inseguro; el mensaje de error dice
qué hacer, no solo qué falta.

**Por qué el login está exento de CSRF.** Todavía no hay sesión que
falsificar, y exigir un token antes de tener una obligaría a una petición
previa solo para eso. El riesgo residual es bajo para un panel local.

**Por qué el mensaje de error no distingue usuario de contraseña.**
Distinguirlos le confirmaría a un atacante qué nombres de usuario son
válidos — el mensaje es siempre "usuario o contraseña incorrectos".

## Alcance: lo que no incluye, y por qué

Decirlo por escrito vale más que simularlo.

| Fuera de alcance | Por qué |
|-------------------|---------|
| MFA / 2FA | Para un laboratorio con un puñado de analistas, Argon2id + bloqueo por intentos alcanzan |
| SSO / LDAP | Requiere infraestructura de directorio que el proyecto no tiene |
| Recuperación de contraseña | No hay servidor de correo; la reposición es `src/manage_users.py password` |
| Alta de usuarios por interfaz | Decisión de diseño, no una carencia |
| Multi-tenancy | Un solo SOC por despliegue |
| TLS para el panel | Se sirve en `127.0.0.1`. `SIEM_TLS=true` activa el flag `Secure` cuando haya un proxy inverso delante |

**Limitación conocida.** Sin TLS, la contraseña viaja en claro entre el
navegador y el servidor. En el despliegue actual eso ocurre dentro de la
misma máquina (loopback), así que no sale a la red — publicar el panel hacia
una red **exige** poner TLS delante.

## Qué se verifica

| Suite | Qué verifica |
|-------|--------------|
| `tests/integration/test_api01_autenticacion.py` | Acceso, roles, sesión, CSRF, fuerza bruta, arranque seguro |
| `tests/unit/test_gestion_usuarios.py` | Almacén, validación, hashing, CLI |

Lo más relevante que estas pruebas certifican: todas las rutas de datos
responden 401 sin sesión (solo `healthz` y `login` son públicas); un
`viewer` que intenta decidir recibe 403 y **no se escribe nada** en el
registro inmutable; dar de baja a un usuario corta su sesión abierta en la
siguiente petición; el bloqueo por intentos alcanza también a la contraseña
correcta (si no, bastaría con seguir probando); cambiar `X-Forwarded-For` no
esquiva el bloqueo; dos sesiones del mismo usuario producen `session_id`
distintos; y el `session_id` del registro no es la cookie real.

### Un artefacto de pruebas que vale la pena conocer

Durante el desarrollo apareció un caso en que un cliente autenticado como
`cata` (auditor) empezaba a verse como `ana` (analyst) y los permisos salían
mal. Resultó ser un **artefacto del cliente de prueba de Flask**, no una
fuga real: `with app.test_client() as c:` activa la preservación del
contexto de petición, y Flask-Login cachea el usuario autenticado en `g` —
con ese contexto en la pila, una petición de *otro* cliente resolvía
`current_user` desde el `g` heredado. Se verificó que sin `with` el
aislamiento es perfecto, las fixtures se corrigieron, y quedó una prueba
vigilando la invariante — porque si alguna vez fuera real sería gravísimo:
decisiones firmadas por quien no las tomó.
