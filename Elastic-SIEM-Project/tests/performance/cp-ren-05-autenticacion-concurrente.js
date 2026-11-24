// CP-REN-05 · Autenticación concurrente. Requisitos: RNF-CONF-06 y RQ-SEC-28.
// Verifica que 50 usuarios virtuales inician sesión a la vez con credenciales válidas (analista00 a
// analista49) sin ningún rechazo, que en paralelo 10 intentos con contraseña errónea del usuario
// descartable victima00x00 se rechazan o bloquean todos (0 aceptados), que X_AUT >= 0,99 y que el almacén
// de usuarios queda íntegro: los 50 vuelven a iniciar sesión después.
// Precondición: malla con `--analistas 50`.
import { check, sleep, http, exec, BASE, JSON_H, CLAVE, iniciarSesion, opcionesComunes, d } from "./comun.js";
import { Counter, Rate } from "k6/metrics";

const PREFIJO = __ENV.K6_PREFIJO_ANALISTA || "analista";
const IMPOSTOR = __ENV.K6_IMPOSTOR || "victima00x00";
const usuario = (i) => `${PREFIJO}${String(i).padStart(2, "0")}`;

const loginValidoOk = new Rate("login_valido_ok");               // 1 por inicio válido: 200
const reingresoOk = new Rate("reingreso_ok");                    // los 50 vuelven a entrar
const impostorRechazado = new Rate("impostor_rechazado");        // 401 o 429
const impostoresAceptados = new Counter("impostores_aceptados"); // 200 con credenciales falsas
const autenticacionCorrecta = new Rate("autenticacion_correcta"); // X_AUT = Aut_OK / Aut_Tot

export const options = {
  ...opcionesComunes,
  scenarios: {
    validos: { executor: "per-vu-iterations", vus: 50, iterations: 1, maxDuration: "1m", exec: "iniciarValido" },
    impostor: { executor: "per-vu-iterations", vus: 1, iterations: 10, maxDuration: "1m", exec: "impostor" },
    reingreso: { executor: "per-vu-iterations", vus: 50, iterations: 1, maxDuration: "1m",
                 startTime: d(20), exec: "reingresar" },
  },
  thresholds: {
    login_valido_ok: ["rate==1"],            // 0 rechazos de usuarios válidos
    reingreso_ok: ["rate==1"],               // el almacén de usuarios queda íntegro
    impostor_rechazado: ["rate==1"],         // 10 de 10 rechazados o bloqueados
    impostores_aceptados: ["count==0"],      // 0 impostores aceptados
    autenticacion_correcta: ["rate>=0.99"],  // X_AUT >= 0,99
  },
};

export function iniciarValido() {
  const i = exec.scenario.iterationInTest;
  const ses = iniciarSesion(usuario(i));
  loginValidoOk.add(ses !== null);
  autenticacionCorrecta.add(ses !== null);
}

export function reingresar() {
  const ses = iniciarSesion(usuario(exec.scenario.iterationInTest));
  reingresoOk.add(ses !== null);
}

export function impostor() {
  const n = exec.scenario.iterationInTest + 1;
  const r = http.post(`${BASE}/api/v1/login`, JSON.stringify({ username: IMPOSTOR, password: `incorrecta-${n}-${CLAVE}` }),
    { headers: JSON_H, tags: { name: "login_impostor" } });
  const rechazado = r.status === 401 || r.status === 429;
  check(r, { "impostor 401 o 429": () => rechazado });
  impostorRechazado.add(rechazado);
  if (r.status === 200) impostoresAceptados.add(1);
  autenticacionCorrecta.add(rechazado);
  sleep(0.2);
}
