# 15 · Autenticación, sesiones y control de acceso

> **Cierra el hallazgo API-01** de la [auditoría](auditoria/01-auditoria-integral.md)
> y los requisitos `RQ-SEC-08`, `RQ-SEC-11`, `RQ-SEC-13` y `RF-DIF-04` de la ERS.
>
> **Fecha:** 17-09-2026 · Verificado en ejecución.

---

## 1. El problema que cierra

Hasta esta versión, el campo `analyst` del registro inmutable salía de una
variable de entorno:

```python
ANALYST = os.getenv("ANALYST_NAME", "analista-soc")
```

Quien corría el proceso decidía qué nombre quedaba firmando cada decisión. La
cadena de hash (hallazgo A-04) garantiza que el registro **no se alteró después
de escribirse**; no garantizaba **quién lo escribió**.

Para un sistema cuya premisa entera es *la IA sugiere, el humano decide y todo
queda trazado*, esa era la brecha más importante: la trazabilidad terminaba en
un nombre que cualquiera podía elegir.

Ahora:

```json
{
  "ts": "2026-09-17T17:30:57+00:00",
  "analyst": "ana",
  "analyst_rol": "analyst",
  "session_id": "12b1217a80fef1f6",
  "user_agent": "Mozilla/5.0 …",
  "decision": "approved",
  "prev_hash": "a3f2…"
}
```

---

## 2. Nota de diseño que conviene leer primero

> **Ningún rol puede ejecutar acciones de contención.**
>
> El control de acceso decide **quién decide**, no quién ejecuta — porque nadie
> ejecuta, nunca. No existe un rol `admin` que "apriete el botón rojo": ese
> botón no existe en el sistema. La ejecución la hace una persona, a mano, fuera
> de la plataforma.

Agregar autenticación **no agregó capacidad de actuar**: agregó identidad a
quien decide. La propiedad de no-autonomía sigue certificada por
`tests/test_no_autonomy.py` (34 pruebas sobre el AST), y dos pruebas nuevas la
refuerzan desde el lado del RBAC:

- `test_ningun_rol_puede_ejecutar_acciones` — recorre la tabla de permisos y
  falla si alguno declara capacidad de ejecución.
- `test_el_decorador_rechaza_un_permiso_de_ejecucion` — `requiere_permiso("ejecutar")`
  lanza excepción: no se puede ni siquiera *declarar* una vista con ese permiso.

---

## 3. Roles y permisos

Los permisos viven en **una tabla** (`siem_auth.PERMISOS`), no dispersos en `if`
por las vistas. Un permiso mal puesto dentro de una función es mucho más difícil
de auditar que una fila de más.

| Rol | Ver triage | Ver auditoría | Decidir | Verificar cadena |
|-----|:----------:|:-------------:|:-------:|:----------------:|
| `viewer` | ✅ | ✅ | ❌ | ❌ |
| `analyst` | ✅ | ✅ | ✅ | ❌ |
| `auditor` | ✅ | ✅ | ❌ | ✅ |

**Por qué el analista no verifica la cadena.** Separación de funciones: quien
decide no debería ser quien certifica que el registro de sus decisiones está
intacto. Es el mismo principio por el que nadie audita su propio trabajo. El
`auditor` ve todo y verifica, pero no decide.

Las vistas exigen **un permiso**, no un rol:

```python
@app.route("/api/v1/decision", methods=["POST"])
@requiere_permiso("decidir")
def api_decision(): ...
```

Pedir el permiso y no el rol es lo que permite cambiar la tabla sin tocar una
sola vista. Si esto exigiera `rol == "analyst"`, agregar un rol nuevo obligaría
a recorrer todos los endpoints.

---

## 4. Cómo se usa

### 4.1 Preparar el entorno

```bash
# 1. Clave de firma de la cookie. SIN ESTO EL PANEL NO ARRANCA.
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
#   → agregar a .env como SECRET_KEY=<valor>

# 2. Crear el primer usuario
export PYTHONPATH="$PWD/.devtools"
python3 manage_users.py crear ana --rol analyst
#   Contraseña (mínimo 12 caracteres): ********
#   ✅ Usuario 'ana' creado con rol 'analyst'.

# 3. Arrancar
python3 dashboard.py     # → http://127.0.0.1:5000/login
```

### 4.2 Gestión de usuarios

```bash
python3 manage_users.py roles                    # qué puede cada rol
python3 manage_users.py listar -v                # usuarios y permisos
python3 manage_users.py crear beto --rol viewer
python3 manage_users.py password ana             # cambiar contraseña
python3 manage_users.py rol ana --rol auditor    # cambiar rol
python3 manage_users.py baja ana                 # desactivar (no borra)
python3 manage_users.py alta ana                 # reactivar
```

**La baja no borra.** Borrar un usuario dejaría decisiones firmadas por alguien
que ya no existe, y el registro es inmutable: no se puede corregir después.

**La baja tiene efecto inmediato.** El almacén se relee en cada petición, así
que la sesión abierta de un usuario dado de baja deja de valer en la siguiente
petición — no hay que esperar a que expire la cookie.

---

## 5. Decisiones técnicas y por qué

| Decisión | Elección | Por qué |
|----------|----------|---------|
| Hash de contraseña | **Argon2id** (`argon2-cffi`, RFC 9106) | `werkzeug` usa scrypt por defecto; Argon2id es el estándar recomendado actual. Los parámetros van versionados en el hash, así que se puede endurecer sin migrar nada |
| Rehash automático | Al iniciar sesión, si los parámetros quedaron viejos | Es el único momento en que la contraseña está disponible en claro |
| Almacén | `users.json`, `0600`, gestionado por CLI | Sin base de datos: mantiene el "cero dependencias de infraestructura". Migrar a SQLite después es trivial |
| Alta de usuarios | Por línea de comandos, no por la web | Crear cuentas es administración del sistema. Exponerlo en la web agrega superficie de ataque para ganar comodidad en algo que se hace una vez por integrante |
| Sesión | `Flask-Login` + cookie firmada | `SECRET_KEY` desde `.env`; el servidor **no arranca** si falta |
| Flags de cookie | `HttpOnly`, `SameSite=Lax`, `Secure` con TLS | `HttpOnly` la hace inaccesible desde JavaScript; `Lax` impide que viaje en un POST de otro sitio |
| CSRF | `Flask-WTF`, token por header `X-CSRFToken` | La API es JSON, así que el token va por header y no por formulario |
| Expiración | 30 min de inactividad · 8 h absoluta | El de inactividad protege una terminal desatendida; el absoluto acota el daño de una cookie robada |
| Anti-fuerza bruta | 5 intentos / 15 min por usuario+IP, con backoff | Es irónico que un sistema que detecta fuerza bruta sea vulnerable a ella |
| IP del cliente | `remote_addr`, **nunca** `X-Forwarded-For` | El encabezado lo pone el cliente: usarlo permitiría esquivar el bloqueo cambiándolo |
| `session_id` en el registro | Resumen derivado, no la cookie | Guardar el identificador real en un archivo append-only sería dejar un token válido a la vista de cualquiera que lea la auditoría |

### 5.1 Por qué `SECRET_KEY` no tiene valor por defecto

Un default haría que todos los despliegues firmaran sus cookies con la misma
clave: cualquiera que conozca el repositorio podría fabricar una sesión válida.
Preferimos que el servidor **no arranque** a que arranque inseguro:

```
dashboard.ConfiguracionInsegura: Falta SECRET_KEY. El panel no arranca sin una
clave de firma de sesión.
Generá una con:  python3 -c "import secrets; print(secrets.token_urlsafe(48))"
y agregala a .env como SECRET_KEY=<valor>.
```

El mensaje dice **qué hacer**, no solo qué falta. Hay una prueba que lo verifica.

### 5.2 Por qué el login está exento de CSRF

Todavía no hay sesión que falsificar, y exigir un token antes de tener una
obligaría a una petición previa solo para eso. El riesgo residual —forzar a
alguien a iniciar sesión como otro— es bajo para un panel local. Está declarado
acá en vez de quedar como un descuido silencioso.

### 5.3 Por qué el mensaje de error no distingue usuario de contraseña

```
usuario inexistente  → "usuario o contraseña incorrectos"
contraseña mala      → "usuario o contraseña incorrectos"
```

Distinguirlos le confirmaría a un atacante qué nombres de usuario son válidos.
Hay una prueba que compara los dos mensajes y falla si divergen.

---

## 6. Alcance: lo que NO incluye, y por qué se declara

Decirlo por escrito vale más que simularlo. **Queda fuera de la v1.0:**

| Fuera de alcance | Por qué |
|------------------|---------|
| MFA / 2FA | Para un laboratorio con un puñado de analistas, la contraseña con Argon2id y el bloqueo por intentos alcanzan |
| SSO / LDAP | Requiere infraestructura de directorio que el proyecto no tiene |
| Recuperación de contraseña | No hay servidor de correo. La reposición es `manage_users.py password` |
| Alta de usuarios por interfaz | Decisión de diseño (§5), no una carencia |
| Multi-tenancy | Un solo SOC por despliegue |
| TLS para el panel | Se sirve en `127.0.0.1`. `SIEM_TLS=true` activa el flag `Secure` cuando haya un proxy inverso delante |

**Limitación conocida que conviene tener presente:** sin TLS, la contraseña viaja
en claro entre el navegador y el servidor. En el despliegue actual eso ocurre
dentro de la misma máquina (loopback), así que no sale a la red. Publicar el
panel hacia una red **exige** poner TLS delante — es `RQ-SEC-01`, hoy parcial.

---

## 7. Qué se verifica

**126 pruebas** cubren esta funcionalidad:

| Suite | Pruebas | Qué verifica |
|-------|--------:|--------------|
| `tests/integration/test_api01_autenticacion.py` | 60 | Acceso, roles, sesión, CSRF, fuerza bruta, arranque seguro |
| `tests/unit/test_gestion_usuarios.py` | 66 | Almacén, validación, hashing, CLI |

Lo más relevante:

- **Las 11 rutas de datos responden 401 sin sesión** (el panel HTML redirige al
  login). Solo `healthz` y `login` son públicas, y hay una prueba que vigila esa
  lista.
- **Un `viewer` que intenta decidir recibe 403 y no se escribe nada** en el
  registro inmutable.
- **Dar de baja a un usuario corta su sesión abierta** en la siguiente petición.
- **El bloqueo por intentos alcanza también a la contraseña correcta** — si no,
  bastaría con seguir probando hasta acertar.
- **Cambiar `X-Forwarded-For` no esquiva el bloqueo.**
- **Dos sesiones del mismo usuario producen `session_id` distintos**: se puede
  distinguir desde dónde se tomó cada decisión.
- **El `session_id` del registro no es la cookie** (prueba explícita).

Resultado de la última corrida: `548 passed, 2 skipped`, cobertura **99 %** en
`siem_auth.py` y **94 %** en `manage_users.py`.

### 7.1 Un artefacto de pruebas que vale la pena conocer

Durante el desarrollo apareció un caso en que un cliente autenticado como `cata`
(auditor) empezaba a verse como `ana` (analyst) y los permisos salían mal.

Resultó ser un **artefacto del cliente de prueba de Flask**, no una fuga real:
`with app.test_client() as c:` activa la preservación del contexto de petición, y
Flask-Login cachea el usuario autenticado en `g`. Con ese contexto en la pila,
una petición de *otro* cliente resolvía `current_user` desde el `g` heredado.

Se verificó que sin `with` el aislamiento es perfecto, las fixtures se
corrigieron, y quedó
`test_las_sesiones_de_distintos_clientes_no_se_mezclan` vigilando la invariante
— porque si alguna vez fuera real sería gravísimo: decisiones firmadas por quien
no las tomó.

---

## 8. Trazabilidad con la ERS

| Requisito | Antes | Ahora |
|-----------|:-----:|:-----:|
| `RQ-SEC-08` — identidad del analista | **[P]** *"sale de una variable de entorno; todas las decisiones se firman igual"* | ✅ **[I]** |
| `RQ-SEC-11` — falsificación de peticiones entre sitios | **[D]** | ✅ **[I]** |
| `RQ-SEC-13` — gestión de sesiones | **[D]** | ✅ **[I]** |
| `RF-DIF-04` — control de acceso por roles | **[D]** | ✅ **[I]** |
| `RQ-SEC-01` — canal cifrado | **[P]** | **[P]** sin cambios: sigue faltando TLS para publicar el panel |

Estos cuatro cambios de estado se suman a los cinco que la
[auditoría §6.1](auditoria/01-auditoria-integral.md) ya había identificado. La
ERS debería actualizarse a **v1.1.0** con los nueve (tarea P11 del
[prompt de trabajo](auditoria/02-prompt-de-trabajo.md)).
