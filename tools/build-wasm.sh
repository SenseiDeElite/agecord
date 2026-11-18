#!/usr/bin/env bash

# This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
# See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE

# build-wasm.sh – builds src/lib/agecord-*.min.js from wasm/

# One WASM module is built per extension component, each containing only the
# functions that component imports. Every Cargo feature of the crate enables
# exactly one exported function (feature name with '-' replaced by '_'), so the
# list of features below is also the list of exports.

# Requires: wasm-pack and esbuild (see docs/DEVELOPMENT.md for pinned versions).

#   tools/build-wasm.sh            build every variant
#   tools/build-wasm.sh sign       i.e. build only the named variant(s)

set -euo pipefail

# Always operate from the repository root (the parent of tools/).
_self="$(realpath -e -- "${BASH_SOURCE[0]}")"
cd -P -- "$(dirname -- "$_self")/.."
ROOT="$(pwd -P)"

CRATE_DIR="wasm"
LIB_DIR="src/lib"

# variant -> consuming component -> features (space separated).
# Keep these in sync with the imports of the listed files.
VARIANT_ORDER=(encrypt vault identity sign)
declare -A VARIANT_FEATURES=(
  # src/background/background.js
  [encrypt]='xchacha20poly1305-encrypt'
  # src/popup/crypto-worker.js
  [vault]='argon2id xchacha20poly1305-encrypt xchacha20poly1305-decrypt'
  # src/popup/popup.js
  [identity]='ml-dsa87-keygen ml-dsa87-verifying-key-from-seed shake256'
  # src/content/file-crypto-worker.js
  [sign]='ml-dsa87-sign ml-dsa87-verify ml-dsa87-verifying-key-from-seed'
)

for tool in wasm-pack esbuild; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' is required but was not found in PATH" >&2
    exit 1
  fi
done

[[ -f "$CRATE_DIR/Cargo.toml" ]] || { echo "error: $CRATE_DIR/Cargo.toml not found" >&2; exit 1; }
[[ -d "$LIB_DIR" ]]              || { echo "error: $LIB_DIR not found" >&2; exit 1; }

# Removes a previous per-variant output dir. Only directories directly under
# $CRATE_DIR/pkg are accepted, and symlinks are refused.
clean_pkg_dir() {
  local dir="$1"
  [[ -e "$dir" ]] || return 0
  if [[ -L "$dir" ]]; then
    echo "error: '$dir' is a symlink, refusing to remove" >&2
    exit 1
  fi
  local real
  real="$(realpath -e -- "$dir")"
  if [[ "$(dirname -- "$real")" != "$ROOT/$CRATE_DIR/pkg" ]]; then
    echo "error: '$real' is not directly under $CRATE_DIR/pkg, refusing to remove" >&2
    exit 1
  fi
  find "$dir" -depth -delete
}

build_variant() {
  local v="$1"
  local features="${VARIANT_FEATURES[$v]:-}"
  if [[ -z "$features" ]]; then
    echo "error: unknown variant '$v' (known: ${VARIANT_ORDER[*]})" >&2
    exit 1
  fi

  local name="agecord_${v}"
  local out_rel="pkg/$v"
  local outfile="$ROOT/$LIB_DIR/agecord-${v}.min.js"
  local csv="${features// /,}"
  local -a exports=()
  local f
  for f in $features; do exports+=("${f//-/_}"); done

  echo "==> [$v] Compiling ($csv)..."
  clean_pkg_dir "$CRATE_DIR/$out_rel"
  (
    cd -- "$CRATE_DIR"
    wasm-pack build --target web --release \
      --out-dir "$out_rel" --out-name "$name" \
      -- --locked --no-default-features --features "$csv"
  )

  echo "==> [$v] Bundling..."
  local entry="$CRATE_DIR/$out_rel/entry.js"
  {
    echo '/*'
    echo ' * This source code is licensed under the MIT License.'
    echo ' * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/wasm/LICENSE'
    echo ' */'
    echo
    echo "import wasmBytes from './${name}_bg.wasm';"
    echo "import __init from './${name}.js';"
    echo
    echo 'export {'
    for f in "${exports[@]}"; do echo "    $f,"; done
    echo "} from './${name}.js';"
    echo
    echo 'export const init = () => __init({ module_or_path: wasmBytes });'
  } > "$entry"

  (
    cd -- "$CRATE_DIR"
    esbuild "$out_rel/entry.js" \
      --bundle \
      --format=esm \
      --minify \
      --charset=utf8 \
      --tree-shaking=true \
      --loader:.wasm=binary \
      --outfile="$outfile"
  )

  echo "==> [$v] Done: $LIB_DIR/agecord-${v}.min.js ($(wc -c < "$outfile") bytes, wasm $(wc -c < "$CRATE_DIR/$out_rel/${name}_bg.wasm") bytes)"
}

if [[ $# -eq 0 ]]; then
  set -- "${VARIANT_ORDER[@]}"
fi
for v in "$@"; do
  build_variant "$v"
done
