#!/bin/bash
# Demuestra que cada regla propia (seccion 6 del documento 1.1) DETECTA una violacion:
# trabaja sobre una COPIA temporal del proyecto, y para cada propiedad
#   1. corre la prueba sobre el codigo sano       -> debe PASAR
#   2. inyecta un defecto en la copia              -> la misma prueba debe FALLAR
# El producto no se modifica. Salidas en reglas-propias/salidas/.
#
# Uso:  VENV=/ruta/al/venv/bin ./ejecutar_mutaciones.sh
set -u
AQUI="$(cd "$(dirname "$0")" && pwd)"
RAIZ="$(cd "$AQUI/../../../.." && pwd)"          # Elastic-SIEM-Project
VENV="${VENV:?definir VENV con la carpeta bin del entorno de herramientas}"
SALIDAS="$AQUI/salidas"; mkdir -p "$SALIDAS"
COPIA="$(mktemp -d)"; trap 'rm -rf "$COPIA"' EXIT

rsync -a --exclude node_modules --exclude .devtools --exclude .venv --exclude .git --exclude data \
      --exclude logs --exclude reportes --exclude entregables --exclude __pycache__ \
      --exclude docs --exclude screenshots --exclude .ruff_cache --exclude .pytest_cache "$RAIZ/" "$COPIA/"
ln -s "$RAIZ/node_modules" "$COPIA/node_modules" 2>/dev/null   # el test de XSS ejecuta Node

correr() { # etiqueta  archivos-de-prueba...
  (cd "$COPIA" && "$VENV/pytest" -q -p no:cacheprovider --no-header -x "$@" 2>&1 | tail -n 12)
}

# mutacion ID "titulo" "archivo-a-mutar" "orden de python para mutar" pruebas...
mutar() {
  local id="$1" titulo="$2" archivo="$3" cmd="$4"; shift 4
  local salida="$SALIDAS/$id.txt"
  cp "$COPIA/$archivo" "$COPIA/$archivo.sano"
  {
    echo "# Propiedad: $titulo"
    echo "# Archivo mutado (en la copia): $archivo"
    echo "# Pruebas: $*"
    echo; echo "## 1. Codigo sano"
    correr "$@"
    echo; echo "## 2. Defecto inyectado: $cmd"
    (cd "$COPIA" && python3 -c "$cmd")
    correr "$@"
    echo; echo "## 3. Diferencia entre el archivo sano y el mutado"
    diff -u "$COPIA/$archivo.sano" "$COPIA/$archivo" | tail -n +3 | head -n 14
  } > "$salida"
  mv "$COPIA/$archivo.sano" "$COPIA/$archivo"      # restaura para la siguiente
  printf '%-30s %s\n' "$id" "$(grep -E '^(FAILED|[0-9]+ (passed|failed))|passed|failed' "$salida" | sed -n '1p;$p' | tr '\n' '|')"
}

mutar M1-no-autonomia "Ningun componente ejecuta procesos (AST)" libs/siem_lib.py \
  "p='libs/siem_lib.py'; s=open(p).read(); open(p,'w').write(s+'\nimport subprocess\nsubprocess.run([\"ls\"], check=True)\n')" \
  tests/test_no_autonomy.py
mutar M2-lista-blanca "Validacion de IP y usuario por lista blanca" libs/siem_validators.py \
  "p='libs/siem_validators.py'; s=open(p).read(); a='return not _METACARACTERES_SHELL & set(valor)'; assert a in s; open(p,'w').write(s.replace(a,'return True'))" \
  tests/unit/test_validators.py tests/unit/test_s01_inyeccion_comandos.py
mutar M3-xss-panel "Ausencia de XSS en el panel (sin handlers inline)" services/gateway/templates/index.html \
  "p='services/gateway/templates/index.html'; s=open(p).read(); a='<body'; i=s.index(a); j=s.index('>',i)+1; open(p,'w').write(s[:j]+'<button onclick=\"alert(document.cookie)\">x</button>'+s[j:])" \
  tests/unit/test_s02_xss_dashboard.py
mutar M4-reglas-sin-acciones "Reglas de deteccion sin acciones automaticas" rules/ndjson/A1-ssh-brute-force-basic-threshold.ndjson \
  "p='rules/ndjson/A1-ssh-brute-force-basic-threshold.ndjson'; s=open(p).read(); a='\"actions\": []'; assert a in s; open(p,'w').write(s.replace(a,'\"actions\": [{\"id\": \"webhook\"}]',1))" \
  tests/unit/test_reglas_como_codigo.py
mutar M5-compose-limites "Limites de memoria en docker-compose.yml" docker-compose.yml \
  "p='docker-compose.yml'; L=open(p).read().split('\n'); i=next(k for k,l in enumerate(L) if 'mem_limit: 512m' in l); del L[i]; open(p,'w').write('\n'.join(L))" \
  tests/unit/test_despliegue_compose.py
mutar M6-keyword "Agregaciones sobre campos .keyword" services/collector/es_client.py \
  "p='services/collector/es_client.py'; s=open(p).read(); a='\"field\": \"source_ip.keyword\"'; assert a in s; open(p,'w').write(s.replace(a,'\"field\": \"source_ip\"'))" \
  tests/unit/test_agregaciones_keyword.py
mutar M7-tokens-css "Uso de tokens de diseno en CSS (sin px sueltos)" services/gateway/static/app.css \
  "p='services/gateway/static/app.css'; s=open(p).read(); open(p,'w').write(s+'\n.mutacion { padding: 7px; }\n')" \
  tests/unit/test_tokens_de_diseno.py
mutar M8-contraste "Contraste WCAG AA" services/gateway/static/tokens.css \
  "p='services/gateway/static/tokens.css'; s=open(p).read(); a='--text:   #c9d1d9;'; assert a in s; open(p,'w').write(s.replace(a,'--text:   #1a1f26;'))" \
  tests/unit/test_contraste_de_la_interfaz.py
