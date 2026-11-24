// CP-REN-07 · Estrés por escalones. Requisito: RNF-RD-09.
// Verifica que hasta 100 usuarios virtuales (escalones de 20, 50 y 100) el sistema responde con menos de
// 1 % de errores y todas las lecturas con p95 < 500 ms, y registra el escalón en el que se supera alguno de
// esos límites (punto de quiebre): los escalones de 150 y 200 se miden pero no tienen umbral, porque ahí
// se busca el quiebre, no se exige el cumplimiento.
// Cada escalón dura 1 min (5 s de subida y 55 s sostenidos). Cada usuario virtual refresca cada 1 a 3 s.
// Precondición: malla reiniciada con 100 incidentes. CP-REN-09 corre al mismo tiempo (sonda de salud).
import { opcionesComunes, d, miSesion, pensar, leer, NOMBRES, transcurrido, ESCALA } from "./comun.js";
import { Rate, Trend } from "k6/metrics";

const ESCALONES = [20, 50, 100, 150, 200];
const CON_UMBRAL = [20, 50, 100];

// Por escalón: una tendencia por endpoint y la tasa de lecturas fallidas.
const tiempos = {}, fallos = {};
for (const e of ESCALONES) {
  fallos[e] = new Rate(`fallos_e${e}`);
  tiempos[e] = Object.fromEntries(NOMBRES.map((n) => [n, new Trend(`t_${n}_e${e}`, true)]));
}

const umbrales = {};
for (const e of CON_UMBRAL) {
  umbrales[`fallos_e${e}`] = ["rate<0.01"];
  for (const n of NOMBRES) umbrales[`t_${n}_e${e}`] = ["p(95)<500"];
}

const etapas = [];
for (const e of ESCALONES) {
  etapas.push({ duration: d(5), target: e }, { duration: d(55), target: e });
}

export const options = {
  ...opcionesComunes,
  scenarios: { estres: { executor: "ramping-vus", startVUs: 0, stages: etapas, gracefulRampDown: "0s" } },
  thresholds: umbrales,
};

const escalonActual = () => ESCALONES[Math.min(ESCALONES.length - 1, Math.floor(transcurrido() / (60000 * ESCALA)))];

export default function () {
  if (!miSesion()) return;
  const e = escalonActual();
  for (const nombre of NOMBRES) {
    const { ok } = leer(nombre, [tiempos[e][nombre]]);
    fallos[e].add(!ok);
  }
  pensar();
}
