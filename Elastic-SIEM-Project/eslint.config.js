// Análisis estático del JavaScript del dashboard (SIEM-IA).
//
// `eslint-plugin-security` cubre el catálogo general (eval, RegExp dinámicas,
// acceso a objetos por índice variable). `eslint-plugin-no-unsanitized` es el
// que importa de verdad acá: detecta asignaciones a innerHTML con contenido no
// literal, que es exactamente el vector del hallazgo S-02 (XSS almacenado vía
// datos de log). El plugin de seguridad, por sí solo, no lo ve.
//
// ⚠️  Alcance actual: hoy el JS vive embebido en `templates/index.html`, que
// ESLint no analiza. Esta configuración apunta a `static/**/*.js` y entra en
// vigor con el refactor R-05 (Fase 3), que extrae el script a su propio archivo.
// Ver docs/11-reporte-fase-0.md §5.2.

import js from "@eslint/js";
import security from "eslint-plugin-security";
import noUnsanitized from "eslint-plugin-no-unsanitized";

export default [
  {
    ignores: ["node_modules/**", ".devtools/**", ".venv/**"],
  },
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ["static/**/*.js"],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "script",
      globals: {
        window: "readonly",
        document: "readonly",
        fetch: "readonly",
        console: "readonly",
        setInterval: "readonly",
        setTimeout: "readonly",
        Date: "readonly",
        Promise: "readonly",
        Map: "readonly",
        Set: "readonly",
        URLSearchParams: "readonly",
        alert: "readonly",
        prompt: "readonly",
      },
    },
    plugins: {
      "no-unsanitized": noUnsanitized,
    },
    rules: {
      // ── Bloqueantes: el vector de S-02 ──
      //
      // `escape.taggedTemplates: ["html"]` declara que el tag `html` de
      // static/app.js es un sanitizador: escapa TODO lo interpolado salvo los
      // `FragmentoSeguro`, que solo ese mismo tag puede producir. No es una
      // excepción para silenciar la regla, es decirle dónde está la frontera de
      // saneamiento — y esa afirmación está verificada por
      // tests/unit/test_s02_xss_dashboard.py, que ejecuta el tag real en Node
      // contra una batería de payloads.
      "no-unsanitized/property": ["error", { escape: { taggedTemplates: ["html"] } }],
      "no-unsanitized/method": ["error", { escape: { taggedTemplates: ["html"] } }],

      // ── Bloqueantes: ejecución de código ──
      "security/detect-eval-with-expression": "error",
      "security/detect-non-literal-require": "error",
      "security/detect-child-process": "error",
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",

      // ── Avisos: patrones a revisar, no siempre explotables ──
      "security/detect-object-injection": "warn",
      "security/detect-non-literal-regexp": "warn",
      "security/detect-unsafe-regex": "error",

      // ── Higiene ──
      "no-unused-vars": ["warn", { argsIgnorePattern: "^_" }],
      "eqeqeq": ["error", "smart"],
      "no-implicit-globals": "off",
    },
  },
];
