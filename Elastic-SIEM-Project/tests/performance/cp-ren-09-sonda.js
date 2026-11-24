// CP-REN-09 · Sonda de salud durante el estrés. Requisito: RNF-COMP-01 (parte medible en la malla).
// Verifica que 1 usuario virtual consultando GET /api/v1/healthz cada 2 s mientras corre CP-REN-07 recibe
// siempre 200 y en menos de 2 s. Se ejecuta AL MISMO TIEMPO que CP-REN-07 (otro proceso de k6) y dura lo
// mismo que sus 5 escalones. El plan limita la exigencia al punto de quiebre de CP-REN-07: el umbral se
// declara sobre toda la corrida y, además, se registra el peor sondeo de cada escalón (sin umbral) para
// poder acotarlo al quiebre al leer el resultado.
import { opcionesComunes, d, http, check, sleep, BASE, CABECERAS, t, transcurrido, ESCALA } from "./comun.js";
import { Trend } from "k6/metrics";

const ESCALONES = [20, 50, 100, 150, 200];
const porEscalon = Object.fromEntries(ESCALONES.map((e) => [e, new Trend(`t_sonda_e${e}`, true)]));

export const options = {
  ...opcionesComunes,
  scenarios: { sonda: { executor: "constant-vus", vus: 1, duration: d(300) } },
  thresholds: {
    t_salud: ["max<2000"],            // cada sondeo en menos de 2 s
    http_req_failed: ["rate==0"],     // cada sondeo responde 200
    checks: ["rate==1"],
  },
};

export default function () {
  const r = http.get(`${BASE}/api/v1/healthz`, { headers: CABECERAS, tags: { name: "salud" } });
  t.salud.add(r.timings.duration);
  porEscalon[ESCALONES[Math.min(4, Math.floor(transcurrido() / (60000 * ESCALA)))]].add(r.timings.duration);
  check(r, { "sonda 200": (x) => x.status === 200 });
  sleep(2 * Math.min(1, ESCALA));
}
