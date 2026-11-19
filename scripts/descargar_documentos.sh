#!/usr/bin/env bash
# Lab 12 - Descarga recursiva de /uploads/ aprovechando el listado de directorios.
# Uso:   ./descargar_documentos.sh [http://localhost:3000]
# Deja todo en ./botin/ con la misma estructura de carpetas del servidor.
BASE="${1:-http://localhost:3000}"
DESTINO="botin"
total=0

recorrer() {                      # $1 = ruta relativa, ej: /uploads/docs/
  local ruta="$1" item
  # Cada enlace del "Index of" es un archivo o una subcarpeta (termina en /)
  for item in $(curl -s "$BASE$ruta" | grep -o 'href="[^"?]*"' | cut -d'"' -f2 | grep -v '^\.\./$'); do
    if [[ "$item" == */ ]]; then
      recorrer "$ruta$item"       # subcarpeta: se recorre igual
    else
      mkdir -p "$DESTINO$ruta"
      curl -s -o "$DESTINO$ruta$item" "$BASE$ruta$item" && echo "  descargado: $ruta$item" && total=$((total + 1))
    fi
  done
}

echo "Recorriendo $BASE/uploads/ ..."
recorrer "/uploads/"
echo "Total: $total archivos en ./$DESTINO/uploads/"

# Variante sin listado: los documentos tienen nombres secuenciales
# for i in $(seq -w 1 40); do curl -s -O "$BASE/uploads/docs/doc0$i.jpg"; done
#
# Variante con wget (una sola linea):
# wget -r -np -nH -R "index.html*" "$BASE/uploads/"
