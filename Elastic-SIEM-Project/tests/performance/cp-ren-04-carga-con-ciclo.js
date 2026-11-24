// CP-REN-04 · Carga con el ciclo del pipeline activo. Requisitos: RNF-RD-05 y RNF-CONF-07.
// Verifica que, con el ciclo del pipeline corriendo cada 120 s, el mismo perfil de CP-REN-02 (20 usuarios
// virtuales, 4 min sostenidos = dos ciclos) mantiene el p95 de GET incidents en no más del doble del de
// CP-REN-02, y que ninguna lectura falla, también en la etapa final de 100 usuarios virtuales durante 1 min.
// Precondición: malla con `--incidentes 100 --ciclo` (collector sin Elasticsearch).
// Variable obligatoria: P95_REN02_INCIDENTES = p95 de t_incidentes de CP-REN-02, en ms.
import { opcionesComunes, d, miSesion, recorrerPanel, pensar, p95De, transcurrido } from "./comun.js";
import { Trend } from "k6/metrics";

const FASE_CARGA_S = 30 + 240;
const t20 = new Trend("t_incidentes_20vu", true);     // informativas: no tienen umbral
const t100 = new Trend("t_incidentes_100vu", true);

export const options = {
  ...opcionesComunes,
  scenarios: {
    carga: { executor: "ramping-vus", startVUs: 0, gracefulRampDown: "0s",
      stages: [{ duration: d(30), target: 20 }, { duration: d(240), target: 20 },
               { duration: d(10), target: 100 }, { duration: d(60), target: 100 },
               { duration: d(20), target: 0 }] },
  },
  thresholds: {
    t_incidentes: [p95De("P95_REN02_INCIDENTES", 2)],   // no más del doble del de CP-REN-02
    lecturas_fallidas: ["rate==0"],                       // ninguna lectura falla durante los ciclos
  },
};

export default function () {
  if (!miSesion()) return;
  const fase = transcurrido() > FASE_CARGA_S * 1000 * Number(__ENV.ESCALA || 1) ? t100 : t20;
  recorrerPanel((nombre) => (nombre === "incidentes" ? [fase] : []));
  pensar();
}
