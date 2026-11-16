#!/usr/bin/env bash

# This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
# See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE

# build.sh – packages agecord into a .crx, .xpi, or source .zip

set -euo pipefail

# Always operate from the repository root (the parent of tools/), no matter
# where the script is invoked from. safe_rm_file below relies on $PWD being
# the root.
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

SRC_DIR="src"
MANIFEST_DIR="manifests"
DIST_DIR="dist"

usage() {
  cat <<'EOF'
Usage: build.sh <chromium|firefox|source>

  chromium   Build a signed .crx for Chromium-based browsers
  firefox    Build a .xpi for Firefox
  source     Build a .zip for source code submission
EOF
  exit 1
}

safe_rm_file() {
  local f="$1"
  [[ -e "$f" ]] || return 0
  if [[ -L "$f" ]]; then
    echo "error: '$f' is a symlink, refusing to remove" >&2
    exit 1
  fi
  # Resolve the real path and require it to live
  # under the current working directory, where build outputs are written.
  local real
  real="$(realpath -e -- "$f")"
  case "$real" in
    "$PWD"/*) ;;
    *)
      echo "error: '$real' is outside the current working directory, refusing to remove" >&2
      exit 1
      ;;
  esac
  if [[ -f "$f" ]]; then
    rm -- "$f"
  else
    echo "error: '$f' exists but is not a plain file, refusing to remove" >&2
    exit 1
  fi
}

# No -rf: rejects unsafe paths and symlinks, then
# uses `find -depth -delete` on a path already confirmed to be a real dir.
safe_rm_dir() {
  local dir="$1"
  [[ -e "$dir" ]] || return 0
  if [[ -L "$dir" ]]; then
    echo "error: '$dir' is a symlink, refusing to remove" >&2
    exit 1
  fi
  # Resolve the real path and require it to live
  # under the system temp area (where mktemp -d put it), rather than
  # trying to block-list every dangerous path it could resolve to.
  local real
  real="$(realpath -e -- "$dir")"
  case "$real" in
    /tmp/*) ;;
    *)
      echo "error: '$real' is outside the expected temp area, refusing to remove" >&2
      exit 1
      ;;
  esac
  if [[ -d "$dir" ]]; then
    find "$dir" -depth -delete
  else
    echo "error: '$dir' exists but is not a directory, refusing to remove" >&2
    exit 1
  fi
}

require_file() {
  local f="$1" what="$2"
  if [[ ! -f "$f" ]]; then
    echo "error: $what not found at '$f'" >&2
    exit 1
  fi
}

# Reads the "version" field out of a manifest JSON file, so build outputs
# can be named agecord-MANIFEST_VERSION.*
get_manifest_version() {
  local manifest_file="$1"
  require_file "$manifest_file" "manifest file"
  python3 - "$manifest_file" <<'PYEOF'
import json
import sys

manifest_file = sys.argv[1]
with open(manifest_file) as f:
    data = json.load(f)

version = data.get("version")
if not version:
    print(f"error: no \"version\" field found in {manifest_file}", file=sys.stderr)
    sys.exit(1)

print(version)
PYEOF
}

# Zips a directory tree into $out.
#   zip_tree OUT ROOT [EXCLUDE_PATTERN ...] [--add=SRC:ARCNAME ...]
# Entries are stored relative to ROOT; excludes match relative paths and prune subtrees.
# --add=SRC:ARCNAME adds SRC as ARCNAME without touching disk; duplicate ARCNAMEs are errors.
zip_tree() {
  local out="$1" root="$2"
  shift 2
  safe_rm_file "$out"
  python3 - "$out" "$root" "$@" <<'PYEOF'
import fnmatch
import os
import sys
import zipfile

out, root, *rest = sys.argv[1:]

excludes = []
adds = []
for arg in rest:
    if arg.startswith("--add="):
        src, arcname = arg[len("--add="):].split(":", 1)
        adds.append((src, arcname))
    else:
        excludes.append(arg)

def excluded(rel):
    rel = rel.replace(os.sep, "/")
    return any(fnmatch.fnmatch(rel, pat) for pat in excludes)

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if not excluded(os.path.relpath(os.path.join(dirpath, d), root))
        ]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root)
            if excluded(rel):
                continue
            zf.write(path, rel.replace(os.sep, "/"))
    for src, arcname in adds:
        if arcname in zf.namelist():
            sys.exit(f"error: '{arcname}' is already in the archive; refusing to overwrite it")
        zf.write(src, arcname)
PYEOF
}

# Each target installs its own manifest as manifest.json
check_src() {
  if [[ ! -d "$SRC_DIR" ]]; then
    echo "error: source directory '$SRC_DIR' not found" >&2
    exit 1
  fi
  if [[ -e "$SRC_DIR/manifest.json" ]]; then
    echo "error: '$SRC_DIR/manifest.json' must not exist; manifests live in '$MANIFEST_DIR/'" >&2
    exit 1
  fi
}

# Bundles the content script as a classic IIFE in the staged tree.
#   bundle_content STAGE
# esbuild inlines content.js, emoji_map.js, highlight_map.js, and WASM crypto into
# $STAGE/content/content.js; inlined sources are then removed. Workers and popup/*
# are ES modules and remain untouched.

bundle_content() {
  local stage="$1"
  local esbuild="${ESBUILD:-esbuild}"
  if ! command -v "$esbuild" >/dev/null 2>&1; then
    echo "error: esbuild not found" >&2
    exit 1
  fi

  local banner
  banner="$(cat <<'BANNER'
/*
 * This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
 * See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE
 */
'use strict';
BANNER
)"

  "$esbuild" "$SRC_DIR/content/content.js" \
    --bundle \
    --format=iife \
    --minify \
    --target=chrome155,firefox159 \
    --charset=utf8 \
    --tree-shaking=true \
    --banner:js="$banner" \
    --outfile="$stage/content/content.js"

  rm -f -- "$stage/content/content-loader.js" \
           "$stage/content/emoji_map.js" \
           "$stage/content/highlight_map.js"
}

build_chromium() {
  local crx3_py="tools/crx3/crx3.py"
  local pem_file="tools/agecord.pem"
  local manifest="$MANIFEST_DIR/chromium.json"
  require_file "$crx3_py" "crx3.py"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_crx="$DIST_DIR/agecord-${version}.crx"

  # not `local`: the EXIT trap below runs after this function returns,
  # when a local variable would already be out of scope
  stage="$(mktemp -d)"
  trap 'safe_rm_dir "$stage"' EXIT

  echo "==> [chromium] Staging a copy of $SRC_DIR/..."
  cp -R --reflink=auto -- "$SRC_DIR"/. "$stage"/

  echo "==> [chromium] Installing $manifest as manifest.json..."
  cp --reflink=auto -- "$manifest" "$stage/manifest.json"

  echo "==> [chromium] Bundling content script (IIFE)..."
  bundle_content "$stage"

  echo "==> [chromium] Packing extension as CRX3..."
  if [[ ! -f "$pem_file" ]]; then
    echo "    No private key found at $pem_file — crx3.py will generate one there."
    echo "    Keep the generated .pem safe: reusing it keeps the extension ID stable."
  fi
  python3 "$crx3_py" "$stage" -o "$out_crx" -p "$pem_file"

  echo "==> [chromium] Done: $out_crx"
}

build_firefox() {
  local manifest="$MANIFEST_DIR/firefox.json"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_xpi="$DIST_DIR/agecord-${version}.xpi"

  # not `local`: the EXIT trap runs after this function returns
  stage="$(mktemp -d)"
  trap 'safe_rm_dir "$stage"' EXIT

  echo "==> [firefox] Staging a copy of $SRC_DIR/..."
  cp -R --reflink=auto -- "$SRC_DIR"/. "$stage"/
  cp --reflink=auto -- "$manifest" "$stage/manifest.json"

  echo "==> [firefox] Bundling content script (IIFE)..."
  bundle_content "$stage"

  echo "==> [firefox] Zipping staged tree..."
  # The PNG icon is only used by the Chromium manifest.
  zip_tree "$out_xpi" "$stage" \
    assets/agecord-512.png

  echo "==> [firefox] Done: $out_xpi"
}

# The source package keeps the repository layout and carries everything a reviewer
# needs to reproduce the build: src/, rustcrypto-wasm/ with its build steps in
# docs/, and this script. Chromium-only files are left out.
build_source() {
  local manifest="$MANIFEST_DIR/firefox.json"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_zip="$DIST_DIR/agecord-${version}.zip"

  echo "==> [source] Zipping source tree..."
  zip_tree "$out_zip" . \
    .git \
    "$DIST_DIR" \
    tests \
    tools/agecord.pem \
    "$MANIFEST_DIR/chromium.json" \
    packaging \
    updates.xml \
    tools/crx3 \
    "$SRC_DIR/assets/agecord-512.png"

  echo "==> [source] Done: $out_zip"
}

[[ $# -ne 1 ]] && usage

CMD="$1"

case "$CMD" in
  chromium) build_chromium ;;
  firefox)  build_firefox ;;
  source)   build_source ;;
  *) usage ;;
esac
