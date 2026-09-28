// Pantalla de inicio de sesión (hallazgo API-01).
//
// El script vive en su propio archivo y no embebido en la plantilla para que
// ESLint pueda analizarlo: eslint-plugin-security y eslint-plugin-no-unsanitized
// apuntan a static/**/*.js. Es el mismo criterio que el refactor R-05 pendiente
// para el panel principal.
//
// Todo el texto que llega del servidor se escribe con textContent, nunca con
// innerHTML: un mensaje de error no puede convertirse en un vector de inyección.

(function () {
  "use strict";

  const form = document.getElementById("form");
  const aviso = document.getElementById("aviso");
  const boton = document.getElementById("enviar");

  function mostrar(mensaje, clase) {
    aviso.textContent = mensaje;
    aviso.className = "aviso " + clase;
  }

  function limpiar() {
    aviso.textContent = "";
    aviso.className = "aviso";
  }

  form.addEventListener("submit", async function (evento) {
    evento.preventDefault();
    limpiar();
    boton.disabled = true;
    boton.textContent = "Verificando…";

    try {
      const respuesta = await fetch("/api/v1/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: document.getElementById("username").value,
          password: document.getElementById("password").value
        })
      });

      const datos = await respuesta.json().catch(function () { return {}; });

      if (respuesta.ok) {
        window.location.href = "/";
        return;
      }

      // 429: el rechazo viene del control de intentos, no de las credenciales.
      if (respuesta.status === 429) {
        mostrar(datos.error || "Demasiados intentos. Esperá unos minutos.", "espera");
      } else {
        mostrar(datos.error || "No se pudo iniciar sesión.", "error");
      }
      document.getElementById("password").value = "";
    } catch {
      mostrar("No se pudo contactar al servidor.", "error");
    } finally {
      boton.disabled = false;
      boton.textContent = "Iniciar sesión";
    }
  });
})();
