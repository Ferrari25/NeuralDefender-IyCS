// Panel de supervisión SIEM-IA — lógica del cliente.
//
// Extraído de `templates/index.html` en el refactor R-05. Vivía embebido en un
// <script> de 498 líneas, que ESLint no analiza: de los dos linters de código
// estático que el proyecto se propuso demostrar, el de JavaScript corría sobre
// cero archivos (hallazgo F-03 de la auditoría).
//
// DOS REGLAS QUE NO SE TOCAN:
//
// 1. Sin handlers inline (S-02). Los datos viajan en atributos `data-*` y se
//    leen con `dataset`, que devuelve texto plano. No existe un contexto
//    JavaScript donde interpolar un dato de log.
// 2. El panel NO EJECUTA NADA. Muestra comandos como texto; aprobar una acción
//    registra una intención. Certificado en tests/test_no_autonomy.py.

// `Map` y no un objeto literal: la clave viene de `attack_type`, que sale de un
// log. Con un objeto, `ATTACK_LABELS["constructor"]` devuelve la función heredada
// del prototipo en vez de caer en el valor por defecto. Es lo que señalaba
// `security/detect-object-injection`, y acá era un problema real aunque menor.
const ATTACK_LABELS = new Map([
  ["ssh_brute_force", "Fuerza bruta SSH"],
  ["port_scan", "Escaneo de puertos"],
  ["credential_harvesting", "Phishing / robo de credenciales"],
  ["suspicious_auth", "Autenticación sospechosa"],
]);
// Icono estable por tipo de ataque (RNF-USA-07). Antes eran emoji: un emoji se
// dibuja como un mapa de bits multicolor propio de cada sistema operativo, cambia
// de forma entre Windows, macOS y Linux y NO hereda el color del texto. En un panel
// donde el color significa severidad, eso compite con la información.
const ATTACK_ICONS = new Map([
  ["ssh_brute_force", "i-candado"],
  ["port_scan", "i-radar"],
  ["credential_harvesting", "i-anzuelo"],
  ["suspicious_auth", "i-interrogacion"],
]);
// El chip de estado mostraba el valor crudo de la API (`approved`, `pending`) en un
// panel en español — y el historial de decisiones, unas líneas más abajo, ya
// traducía. La marca ✔ / ✘ hace que el estado no dependa solo del color: quien no
// distingue verde de rojo igual lo lee.
const ESTADO_TEXTO = new Map([
  ["pending", "pendiente"],
  ["approved", "✔ aprobada"],
  ["dismissed", "✘ descartada"],
]);
const estadoTexto = s => ESTADO_TEXTO.get(s) || s;

// La severidad que se pinta, en un solo lugar. La misma cadena de respaldos estaba
// repetida en SEIS sitios, y al quitar las procedencias inventadas (D-11) cualquiera
// de los seis podía degradar un incidente a MEDIUM sin que se notara.
//
// El orden importa, de más específico a más general:
//   1. lo que ajustó el Agente 2
//   2. la severidad que trajo la alerta de Elastic, si la hubo
//   3. la del Agente 1, que SIEMPRE existe — es determinística
//   4. MEDIUM, que a esta altura significa "algo se rompió"
const SEV_DETERMINISTICA = new Map([
  ["critica", "CRITICAL"], ["alta", "HIGH"], ["media", "MEDIUM"], ["baja", "LOW"],
]);
const severidadDe = inc => (
  inc?.analysis?.severidad_ajustada
  || inc?.severity_siem
  || SEV_DETERMINISTICA.get(inc?.classification?.severity)
  || "MEDIUM"
).toUpperCase();

// Procedencia de la detección. `rule_name` solo tiene valor cuando el incidente se
// construyó desde una alerta REAL de Elastic. El Agente 1 no inventa una: antes sí
// lo hacía, y el panel mostraba como «regla SIEM» un nombre que no existía en
// Kibana (D-11).
const procedenciaDe = inc => inc.detection_source === "elastic" && inc.rule_name
  ? html`Elastic SIEM · regla <b>${inc.rule_name}</b>${
      inc.severity_siem ? html` · severidad ${inc.severity_siem}` : ""}${
      inc.risk_score ? html` · riesgo ${inc.risk_score}` : ""}`
  : html`Agente 1 · detección determinística <span class="sutil">(sin alerta de Kibana asociada)</span>`;

const attackLabel = t => ATTACK_LABELS.get(t) || "Otro";
const attackIcon  = t => ico(ATTACK_ICONS.get(t) || "i-advertencia");
function mitreLink(mitre) {
  const id = mitre?.technique_id;
  if (!id) return "—";
  const name = mitre?.technique || "";
  const ruta = encodeURIComponent(id.replace('.', '/'));
  return html`<a href="https://attack.mitre.org/techniques/${new FragmentoSeguro(ruta)}/" target="_blank" rel="noopener">${id}</a> ${name}`;
}
// Escrita en forma desarrollada y no como `\d{1,3}(?:\.\d{1,3}){3}`: son
// equivalentes, pero `safe-regex` (el analizador detrás de
// `security/detect-unsafe-regex`) calcula la altura de estrella y marca el grupo
// repetido aunque sus cuantificadores internos estén acotados. Se midió que la
// versión original era lineal —0,1 ms sobre 5 000 caracteres patológicos—, así
// que era un falso positivo; aun así, la forma desarrollada se analiza sola y no
// obliga a nadie a repetir esa medición.
const IP_RE = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g;
function highlightLog(text) {
  // Escapa primero y resalta después: el marcado que agrega es propio, no del log.
  return new FragmentoSeguro(
    esc(text).replace(IP_RE, m => `<span class="ip-hl">${m}</span>`));
}
function fpHint(level) {
  const l = (level || "").toUpperCase();
  if (l === "LOW") return "(alta confianza — acción segura de aprobar)";
  if (l === "HIGH") return "(revisar con cuidado antes de actuar)";
  if (l === "MEDIUM") return "(confirmar evidencia antes de aprobar)";
  return "";
}
const sevClass = s => "b-" + (s || "MEDIUM").toUpperCase();
// S-02: la versión anterior escapaba & < > " pero NO la comilla simple, y los
// valores se interpolaban dentro de onclick="...('${...}')". Un incident_id con
// una comilla simple cerraba el string JS y ejecutaba código en la sesión del
// analista. Se escapan también ' ` = / — y, sobre todo, ya no hay handlers
// inline donde interpolar datos (ver `delegar()` más abajo).
const ESC_MAP = new Map([
  ["&", "&amp;"], ["<", "&lt;"], [">", "&gt;"], ['"', "&quot;"],
  ["'", "&#39;"], ["`", "&#96;"], ["=", "&#61;"], ["/", "&#47;"],
]);
const esc = s => (s ?? "").toString().replace(/[&<>"'`=/]/g, c => ESC_MAP.get(c));

// ─── Plantilla etiquetada: escapar por construcción ─────────────────────────
//
// Antes, cada valor interpolado se envolvía a mano en `esc()`. Funcionaba, pero
// la seguridad dependía de no olvidarse nunca: UN `${valor}` sin `esc()` en 500
// líneas es un XSS. `no-unsanitized/property` marcó los siete `innerHTML` por
// eso — y tenía razón sobre la fragilidad, aunque hoy no faltara ninguno.
//
// Con `html` el escape es estructural: TODO lo interpolado se escapa salvo que
// sea un `FragmentoSeguro`, que solo puede producir este mismo tag. Olvidarse
// deja de ser posible.

class FragmentoSeguro {
  constructor(texto) { this.texto = texto; }
  toString() { return this.texto; }
}

function interpolar(valor) {
  if (valor === null || valor === undefined || valor === false) return "";
  if (valor instanceof FragmentoSeguro) return valor.texto;   // ya es HTML confiable
  if (Array.isArray(valor)) return valor.map(interpolar).join("");
  return esc(valor);                                          // todo lo demás, escapado
}

function html(partes, ...valores) {
  // `entries()` en vez de indexar con un contador: recorrer con `valores[i]`
  // disparaba `security/detect-object-injection`. Acá era inofensivo (el índice
  // es un entero del propio bucle), pero la forma iterada es más clara y deja el
  // análisis estático sin ruido que después nadie mira.
  let salida = partes[0];
  for (const [i, valor] of valores.entries()) {
    salida += interpolar(valor) + partes[i + 1];
  }
  return new FragmentoSeguro(salida);
}

// Un icono del sprite (`templates/_iconos.html`). Devuelve un `FragmentoSeguro`
// porque el marcado es SVG, no texto: el identificador sale SIEMPRE de un mapa
// cerrado de este archivo y nunca de datos del servidor. El patrón lo deja
// explícito —para quien lee y para el análisis estático— en vez de confiar en que
// nadie le pase otra cosa.
function ico(id) {
  if (!/^i-[a-z]+$/.test(id)) throw new Error(`identificador de icono inválido: ${id}`);
  return new FragmentoSeguro(`<svg class="ico" aria-hidden="true"><use href="#${id}"></use></svg>`);
}

// Asigna un fragmento al DOM. Exige un `FragmentoSeguro`: un string suelto se
// rechaza, porque sería contenido que nadie garantizó que esté escapado.
function pintar(nodo, fragmento) {
  if (!(fragmento instanceof FragmentoSeguro)) {
    throw new TypeError("pintar() solo acepta fragmentos construidos con html``");
  }
  // La asignación pasa por el propio tag: así `no-unsanitized/property` puede
  // comprobar por sí mismo que lo asignado salió del sanitizador, en vez de que
  // se lo silencie con un comentario. El DOM convierte el fragmento a texto con
  // su `toString()`.
  nodo.innerHTML = html`${fragmento}`;
}

const hhmmss = ts => { const m = /T(\d{2}:\d{2}:\d{2})/.exec(ts || ""); return m ? m[1] : (ts ?? ""); };

function timeAgo(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (isNaN(d)) return esc(ts);
  const s = Math.max(0, Math.floor((Date.now() - d.getTime()) / 1000));
  if (s < 60) return "hace segundos";
  if (s < 3600) return `hace ${Math.floor(s/60)}m`;
  if (s < 86400) return `hace ${Math.floor(s/3600)}h`;
  return `hace ${Math.floor(s/86400)}d`;
}

// Sesión vigente: quién está conectado, qué permisos tiene y el token CSRF
// que hay que mandar en cada POST.
let sesion = { usuario: null, rol: null, permisos: [], csrf_token: null };

async function cargarSesion() {
  const r = await fetch("/api/v1/me");
  if (r.status === 401) { window.location.href = "/login"; return false; }
  sesion = await r.json();

  const caja = document.getElementById("sesion");
  caja.textContent = "";
  const nombre = document.createElement("b");
  nombre.textContent = sesion.usuario;
  const rol = document.createElement("span");
  rol.className = "rol";
  rol.textContent = sesion.rol;
  caja.append(nombre, rol);

  // Un rol sin permiso para decidir no ve botones que no puede usar.
  if (!sesion.permisos.includes("decidir")) {
    document.body.classList.add("solo-lectura");
  }
  return true;
}

document.getElementById("salir").addEventListener("click", async () => {
  await fetch("/api/v1/logout", {
    method: "POST",
    headers: { "X-CSRFToken": sesion.csrf_token || "" }
  });
  window.location.href = "/login";
});

let lastData = { incidents: [] };
let selectedId = null;
const collapsed = new Map(); // estado de colapso de evidencia por incidente

async function load() {
  const [incR, decR] = await Promise.all([
    fetch("/api/v1/incidents"), fetch("/api/v1/decisions")]);
  if (incR.status === 401 || decR.status === 401) {
    window.location.href = "/login"; return;
  }
  lastData = await incR.json();
  lastData._decisions = await decR.json();
  populateTypeFilter(lastData.incidents || []);
  render();
}

function populateTypeFilter(incs) {
  const sel = document.getElementById("fType");
  const current = sel.value;
  const types = [...new Set(incs.map(i => i.classification?.attack_type).filter(Boolean))];
  pintar(sel, html`<option value="">Todos los tipos de ataque</option>${
    types.map(t => html`<option value="${t}">${attackLabel(t)}</option>`)}`);
  sel.value = current;
}

function applyFilters() { render(); }

function filteredIncidents() {
  const incs = lastData.incidents || [];
  const sev = document.getElementById("fSeverity").value;
  const type = document.getElementById("fType").value;
  const q = document.getElementById("fSearch").value.trim().toLowerCase();
  return incs.filter(inc => {
    const s = severidadDe(inc);
    if (sev && s !== sev) return false;
    if (type && inc.classification?.attack_type !== type) return false;
    if (q) {
      const hay = [inc.source_ip, ...(inc.attacker_ips || [])].join(" ").toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function render() {
  const incs = lastData.incidents || [];
  const mode = lastData.analyst_mode;
  const badge = document.getElementById("modeBadge");
  if (mode === "gemini") {
    pintar(badge, html`<span class="punto"></span> IA (Gemini)`);
    badge.className = "mode-badge mode-gemini";
  } else if (mode === "fallback") {
    pintar(badge, html`<span class="punto"></span> Fallback determinístico`);
    badge.className = "mode-badge mode-fallback";
  } else {
    badge.textContent = "— sin análisis todavía —";
    badge.className = "mode-badge";
  }
  document.getElementById("meta").textContent = `actualizado ${new Date().toLocaleTimeString()}`;

  renderSummary(incs);
  renderEventsTable(filteredIncidents());
  renderDetail(incs);
  renderRecentAttacks(incs);
  renderLogFeed(incs);
  renderDecisionHistory(lastData._decisions || []);
}

const SEV_ETIQUETA = new Map([
  ["CRITICAL", "críticos"], ["HIGH", "altos"], ["MEDIUM", "medios"], ["LOW", "bajos"],
]);
const plural = (n, singular, plural_) => `${n} ${n === 1 ? singular : plural_}`;

// El resumen tenía SIETE recuadros del mismo tamaño y el mismo peso: Incidentes,
// Acciones, Pendientes, Críticos, Altos, Medios, Bajos. Nada estaba destacado, y como
// las severidades suelen concentrarse, tres de los siete mostraban 0 con la misma
// prominencia que el número que importa.
//
// El número que importa es UNO: cuántas acciones esperan una decisión humana. Es lo
// que este panel existe para resolver. El resto es contexto, y va más chico.
function renderSummary(incs) {
  const caja = document.getElementById("summary");
  const barra = html`<div class="toolbar">↻ auto cada 15s</div>`;

  // Con siete ceros el panel no decía nada. Ahora dice qué hacer.
  if (!incs.length) {
    pintar(caja, html`
      <div class="resumen-vacio">Sin incidentes en la ventana de 24 horas.
        Generá uno con <code>./scripts/demo-ataque.sh</code>.</div>
      ${barra}`);
    return;
  }

  const totalActions = incs.reduce((a, i) => a + (i.recommended_actions || []).length, 0);
  const pending = incs.reduce((a, i) =>
    a + (i.recommended_actions || []).filter(x => x.status === "pending").length, 0);
  // `Map` con las cuatro severidades conocidas: una severidad inesperada no crea
  // una clave nueva ni toca el prototipo (era otro `detect-object-injection`).
  const porSeveridad = new Map([["CRITICAL", 0], ["HIGH", 0], ["MEDIUM", 0], ["LOW", 0]]);
  incs.forEach(i => {
    const s = severidadDe(i);
    if (porSeveridad.has(s)) porSeveridad.set(s, porSeveridad.get(s) + 1);
  });

  // La barra es proporcional, así que su medida sale de los datos y no puede vivir en
  // la hoja de estilos. Viaja como propiedad personalizada —un dato con nombre— y no
  // como una declaración CSS en línea; `.seg { flex: var(--dato-n) 1 0 }` la consume.
  // El prefijo `--dato-` la distingue de un token de diseño.
  const segmentos = [...porSeveridad]
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => html`<span class="seg sev-${sev}" style="--dato-n:${n}"></span>`);

  // La leyenda lista las CUATRO, incluidas las que están en cero: un cero informa
  // ("miramos y no hay críticos"). Lo que cambia es que deja de competir.
  const leyenda = [...porSeveridad].map(([sev, n]) => html`
    <li class="${n ? "" : "cero"}">
      <span class="punto sev-${sev}"></span><b>${n}</b> ${SEV_ETIQUETA.get(sev)}
    </li>`);

  pintar(caja, html`
    <div class="principal ${pending ? "hay-pendientes" : ""}">
      <div class="n">${pending}</div>
      <div class="l">${pending === 0 ? "sin decisiones pendientes"
                     : pending === 1 ? "acción espera tu decisión"
                                     : "acciones esperan tu decisión"}</div>
    </div>
    <div class="secundarias">
      <div class="par">${plural(incs.length, "incidente", "incidentes")}</div>
      <div class="par">${plural(totalActions, "acción sugerida", "acciones sugeridas")}</div>
    </div>
    <div class="severidad">
      <div class="barra" aria-hidden="true">${segmentos}</div>
      <ul class="leyenda">${leyenda}</ul>
    </div>
    ${barra}`);
}

function renderEventsTable(incs) {
  const wrap = document.getElementById("eventsTableWrap");
  if (!incs.length) {
    pintar(wrap, html`<div class="empty">No hay eventos que coincidan con el filtro.</div>`);
    return;
  }
  pintar(wrap, html`
    <table class="events">
      <thead><tr>
        <th>ID</th><th>Estado</th><th>IP origen</th><th>Tipo de ataque</th><th>Análisis de IA</th>
      </tr></thead>
      <tbody>
        ${incs.map(rowHtml)}
      </tbody>
    </table>`);
}

function rowHtml(inc) {
  const sev = severidadDe(inc);
  const excerpt = (inc.analysis?.explicacion || "").split(". ")[0];
  const sel = inc.incident_id === selectedId ? "selected" : "";
  const campaign = (inc.related_incidents || []).length
    ? html`<span class="campaign-icon" title="Parte de una campaña de ${inc.related_incidents.length + 1} incidentes">${ico("i-enlace")}</span>` : "";
  // RNF-USA-08: la fila es interactiva, así que se anuncia como tal y se puede
  // alcanzar con el tabulador. Antes era un <tr> con un manejador y nada más:
  // invisible para quien navega con teclado o con lector de pantalla.
  return html`
    <tr class="${sel}" data-accion="seleccionar" data-incidente="${inc.incident_id}"
        role="button" tabindex="0"
        aria-label="Abrir el detalle del incidente ${inc.incident_id}">
      <td class="ip-mono">${inc.incident_id}${campaign}</td>
      <td><span class="badge ${sevClass(sev)}">${sev}</span></td>
      <td class="ip-mono">${inc.source_ip}</td>
      <td>${attackIcon(inc.classification?.attack_type)} ${attackLabel(inc.classification?.attack_type)}</td>
      <td class="ai-excerpt">${excerpt || "—"}</td>
    </tr>`;
}

function selectIncident(id) {
  selectedId = (selectedId === id) ? null : id;
  render();
  if (selectedId) document.getElementById("detailWrap").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function renderDetail(incs) {
  const wrap = document.getElementById("detailWrap");
  const inc = incs.find(i => i.incident_id === selectedId);
  if (!inc) { pintar(wrap, html``); return; }
  pintar(wrap, html`${renderCard(inc)}`);
}

function renderCard(inc) {
  const an = inc.analysis || {};
  const sev = severidadDe(inc);
  const actions = (inc.recommended_actions || []).map(a => renderAction(inc, a));
  const refs = (an.referencias || []).join(", ");
  const factores = inc.classification?.factores || [];
  return html`
    <div class="card">
      <div class="card-head">
        <span class="badge ${sevClass(sev)}">${sev}</span>
        <span class="title">${attackIcon(inc.classification?.attack_type)} ${attackLabel(inc.classification?.attack_type)}</span>
        <span class="id">${inc.incident_id}</span>
        <span class="src">origen ${inc.source_ip} · atacante ${(inc.attacker_ips||[]).join(", ") || "?"}</span>
        <button class="close" type="button" data-accion="seleccionar"
                data-incidente="${inc.incident_id}">cerrar ✕</button>
      </div>
      <div class="card-body">
        ${renderCampaignBanner(inc)}
        <div class="grid">
          <span class="k">Detección</span><span>${procedenciaDe(inc)}</span>
          <span class="k">Eventos</span><span>${(inc.event_count||0).toLocaleString()}</span>
          <span class="k">MITRE ATT&amp;CK</span><span>${mitreLink(inc.mitre)}</span>
          <span class="k">Falso pos.</span><span>${an.falso_positivo_probabilidad || "—"} <span class="fp-hint">${fpHint(an.falso_positivo_probabilidad)}</span></span>
          <span class="k">Ventana</span><span>${inc.first_seen} → ${inc.last_seen}</span>
        </div>
        <div class="analysis">
          <p><span class="lbl">Qué pasó:</span> ${an.explicacion}
             <span class="src-tag">${an._source || "—"}</span></p>
          <p><span class="lbl">Metodología:</span> ${an.metodologia}</p>
          <p><span class="lbl">Riesgo en este entorno:</span> ${an.contexto_riesgo}</p>
          ${refs ? html`<p><span class="lbl">Referencias:</span> ${refs}</p>` : ""}
          ${an.contexto_historico ? html`<p><span class="lbl">${ico("i-reloj")} Antecedentes de esta IP:</span> ${an.contexto_historico}</p>` : ""}
        </div>
        ${factores.length ? html`
        <div class="factors">
          <div class="ev-section-title">${ico("i-idea")} Por qué esta severidad (explicabilidad del Agente 1)</div>
          <ul>${factores.map(f => html`<li>${f}</li>`)}</ul>
        </div>` : ""}
        ${renderEvidence(inc)}
        <div class="actions">
          <h3>Acciones sugeridas — el analista decide</h3>
          ${actions}
        </div>
      </div>
    </div>`;
}

function renderCampaignBanner(inc) {
  const related = inc.related_incidents || [];
  if (!related.length) return "";
  const ips = (inc.campaign_shared_ips || []).join(", ");
  const links = related.map((id, i) =>
    html`${i ? new FragmentoSeguro(", ") : ""}<a href="#" data-accion="seleccionar" data-incidente="${id}">${id}</a>`);
  return html`
    <div class="campaign-banner">
      ${ico("i-enlace")} <b>Parte de una campaña de ${related.length + 1} incidentes</b> — comparte la IP
      <span class="ip-hl">${ips}</span> con: ${links}.
      Evaluar el conjunto, no cada incidente por separado.
    </div>`;
}

function renderEvidence(inc) {
  const ev = inc.evidence || [];
  const ports = inc.scanned_ports || [];
  const urls = inc.phishing_urls || [];
  const users = inc.target_users || [];
  const samples = inc.sample_messages || [];
  const evId = "ev-" + inc.incident_id;

  const timeline = ev.length
    ? html`<div class="ev-section-title">Cronología (${ev.length} eventos observados)</div>
       <ul class="timeline">${ev.map(e =>
         html`<li><span class="t">${hhmmss(e.ts)}</span><span class="d">${highlightLog(e.detail)}</span></li>`)}</ul>`
    : (samples.length
        ? html`<div class="ev-section-title">Muestras de log</div>
           <ul class="timeline">${samples.map(m => html`<li><span class="d">${highlightLog(m)}</span></li>`)}</ul>`
        : "");

  const chips = (titulo, valores) => valores.length
    ? html`<div class="ev-section-title">${titulo}</div>
       <div class="chips">${valores.map(v => html`<span class="chip">${v}</span>`)}</div>` : "";
  const portsBlock = chips(`Puertos sondeados (${ports.length})`, ports);
  const urlsBlock = chips("URLs de phishing", urls);
  const usersBlock = chips("Usuarios objetivo", users);

  const isCol = collapsed.get(evId);
  return html`
    <div class="evidence">
      <button class="ev-head" type="button" data-accion="evidencia" data-evidencia="${evId}"
              aria-expanded="${isCol ? "false" : "true"}" aria-controls="${evId}">
        <span class="chev" id="${evId}-chev">${isCol ? "▸" : "▾"}</span> ${ico("i-lupa")} Evidencia / por qué se sugieren estas acciones
      </button>
      <div class="ev-body${isCol ? " oculto" : ""}" id="${evId}">
        <div class="ev-why"><b>Motivo de la detección:</b> ${inc.classification?.rationale || "—"}</div>
        ${timeline}${portsBlock}${urlsBlock}${usersBlock}
      </div>
    </div>`;
}

function renderAction(inc, a) {
  const cmd = a.comando_sugerido
    ? html`<div class="cmd">$ ${a.comando_sugerido}</div>${
        a.comando_explicacion ? html`<div class="cmd-explain"><b>Qué hace:</b> ${a.comando_explicacion}</div>` : ""}`
    : "";
  const decided = a.decided_at
    ? html`<div class="decided">por ${a.decided_by} · ${a.decided_at}${a.note ? ` · nota: ${a.note}` : ""}</div>` : "";
  return html`
    <div class="action">
      <div class="top">
        <span class="state s-${a.status}">${estadoTexto(a.status)}</span>
        <span class="who">${a.responsable} · ${a.plazo}</span>
        <span class="desc">${a.orden}. ${a.accion}</span>
        <span class="ctrl">
          <button class="approve ${a.status==='approved'?'on':''}" type="button"
            data-accion="decidir" data-decision="approved"
            data-incidente="${inc.incident_id}" data-action-id="${a.action_id}">Aprobar</button>
          <button class="dismiss ${a.status==='dismissed'?'on':''}" type="button"
            data-accion="decidir" data-decision="dismissed"
            data-incidente="${inc.incident_id}" data-action-id="${a.action_id}">Descartar</button>
        </span>
      </div>
      ${cmd}${decided}
    </div>`;
}

function renderRecentAttacks(incs) {
  const box = document.getElementById("recentAttacks");
  const recent = [...incs].sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || "")).slice(0, 8);
  if (!recent.length) { pintar(box, html`<div class="meta">Sin actividad todavía.</div>`); return; }
  pintar(box, html`${recent.map(inc => {
    const sev = severidadDe(inc);
    return html`
      <div class="recent-item">
        <span class="icon">${attackIcon(inc.classification?.attack_type)}</span>
        <div class="body">
          <div class="ip">${inc.source_ip} <span class="badge ${sevClass(sev)}">${sev}</span></div>
          <div class="type">${attackLabel(inc.classification?.attack_type)}</div>
        </div>
        <div class="when">${timeAgo(inc.last_seen)}</div>
      </div>`;
  })}`);
}

function renderDecisionHistory(decisions) {
  const box = document.getElementById("decisionHistory");
  if (!decisions.length) {
    pintar(box, html`<div class="meta">Todavía no se registraron decisiones.</div>`); return;
  }

  // El archivo decisions.jsonl es append-only a propósito (auditoría completa, nunca se
  // borra nada) — pero este panel es un resumen de "estado actual", no el log crudo: si el
  // analista aprueba/descarta la MISMA acción varias veces, acá solo mostramos la última,
  // igual que ya hace dashboard.py para el estado de cada acción (replay del log).
  const latestByAction = new Map();
  const revisions = new Map();
  for (const d of decisions) {
    if (!d.action_id) continue;
    revisions.set(d.action_id, (revisions.get(d.action_id) || 0) + 1);
    const prev = latestByAction.get(d.action_id);
    if (!prev || (d.ts || "") > (prev.ts || "")) latestByAction.set(d.action_id, d);
  }

  const sorted = [...latestByAction.values()]
    .sort((a, b) => (b.ts || "").localeCompare(a.ts || "")).slice(0, 12);
  pintar(box, html`${sorted.map(d => {
    const revCount = revisions.get(d.action_id) || 1;
    const revNote = revCount > 1 ? html` <span class="fp-hint">(revisado ${revCount}×)</span>` : "";
    return html`
    <div class="decision-item">
      <span class="dec-${d.decision}">${d.decision === "approved" ? "✔ Aprobada" : "✘ Descartada"}</span>
      — ${d.incident_id}${revNote}
      <div class="who">${d.analyst} · ${hhmmss(d.ts)}${d.note ? ` · ${d.note}` : ""}</div>
    </div>`;
  })}`);
}

function renderLogFeed(incs) {
  const box = document.getElementById("logFeed");
  if (!incs.length) {
    pintar(box, html`<div class="empty">No hay eventos registrados. Corré
      <code>python3 siem_pipeline.py</code> para generarlos.</div>`);
    return;
  }
  const sorted = [...incs].sort((a, b) => (b.last_seen || "").localeCompare(a.last_seen || ""));
  pintar(box, html`${sorted.map(renderFeedItem)}`);
}

function renderFeedItem(inc) {
  const an = inc.analysis || {};
  const sev = severidadDe(inc);
  const ev = (inc.evidence && inc.evidence.length) ? inc.evidence
    : (inc.sample_messages || []).map(s => ({ ts: inc.first_seen, detail: s }));
  const lines = ev.slice(0, 10).map(e =>
    html`<li><span class="t">${hhmmss(e.ts)}</span><span>${highlightLog(e.detail)}</span></li>`);
  const primary = (inc.recommended_actions || [])[0];
  const suggestion = primary ? html`
    <div class="suggestion">
      <div class="txt"><b>Sugerencia de IA:</b> ${an.accion_recomendada || primary.accion}
        <span class="state s-${primary.status}">${estadoTexto(primary.status)}</span></div>
      <button class="small approve ${primary.status==='approved'?'on':''}" type="button"
        data-accion="decidir" data-decision="approved"
        data-incidente="${inc.incident_id}" data-action-id="${primary.action_id}">Aprobar</button>
      <button class="small dismiss ${primary.status==='dismissed'?'on':''}" type="button"
        data-accion="decidir" data-decision="dismissed"
        data-incidente="${inc.incident_id}" data-action-id="${primary.action_id}">Descartar</button>
    </div>` : "";
  return html`
    <div class="feed-item">
      <div class="fi-head">
        <span class="badge ${sevClass(sev)}">${sev}</span>
        <span class="title">${attackIcon(inc.classification?.attack_type)} ${attackLabel(inc.classification?.attack_type)}</span>
        <span class="meta">${inc.incident_id}</span>
        <span class="src">${inc.source_ip}</span>
      </div>
      <ul class="feed-lines">${lines.length ? lines : html`<li>Sin detalle de eventos individuales.</li>`}</ul>
      ${suggestion}
    </div>`;
}

function toggleAbout() {
  document.getElementById("aboutPanel").classList.toggle("open");
}

function toggleEv(evId) {
  collapsed.set(evId, !collapsed.get(evId));
  render();
}

async function decide(incident_id, action_id, decision) {
  let note = "";
  if (decision === "dismissed") note = prompt("Motivo (opcional) para descartar:") || "";
  const r = await fetch("/api/v1/decision", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // CSRF: la cookie es SameSite=Lax, pero el token es la defensa que no
      // depende del navegador del analista.
      "X-CSRFToken": sesion.csrf_token || ""
    },
    body: JSON.stringify({ incident_id, action_id, decision, note })
  });
  if (r.status === 401) { window.location.href = "/login"; return; }
  if (!r.ok) {
    const datos = await r.json().catch(() => ({}));
    alert(datos.error || "No se pudo registrar la decisión.");
  }
  load();
}

// S-02: delegación de eventos. Los datos viajan en atributos `data-*` y se leen
// con `dataset`, que devuelve texto plano — nunca se evalúan como código. Es la
// corrección estructural: ya no existe un lugar donde interpolar un dato de log
// dentro de un contexto JavaScript.
function delegar(evt) {
  const el = evt.target.closest("[data-accion]");
  if (!el) return;
  const { accion, incidente, evidencia, actionId, decision } = el.dataset;

  if (accion === "seleccionar") {
    evt.preventDefault();
    selectIncident(incidente);
  } else if (accion === "decidir") {
    evt.stopPropagation();
    decide(incidente, actionId, decision);
  } else if (accion === "evidencia") {
    toggleEv(evidencia);
  } else if (accion === "about") {
    toggleAbout();
  }
}

document.addEventListener("click", delegar);

// Filtros: mismo criterio, sin handlers inline.
for (const el of document.querySelectorAll("[data-filtro]")) {
  el.addEventListener(el.tagName === "INPUT" ? "input" : "change", applyFilters);
}

(async () => {
  if (await cargarSesion()) {
    load();
    setInterval(load, 15000);
  }
})();
