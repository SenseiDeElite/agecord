#!/usr/bin/env bash

# This source code is licensed under the GNU General Public License v3.0 (GPL-3.0).
# See the full license text: https://github.com/SenseiDeElite/agecord/blob/main/LICENSE

# build.sh – packages agecord into a .crx, .xpi, or source .zip

set -euo pipefail

# Always operate from the repository root (the parent of tools/), no matter
# where the script is invoked from or through which symlinks it is reached.
# `realpath` resolves symlinks to the script itself and `cd -P` makes $PWD the
# physical path, so ROOT can be compared against `realpath` results below.
_self="$(realpath -e -- "${BASH_SOURCE[0]}")"
cd -P -- "$(dirname -- "$_self")/.."
ROOT="$(pwd -P)"

SRC_DIR="src"
MANIFEST_DIR="manifests"
DIST_DIR="dist"

# Source package ALLOWLIST. Only files matching one of these patterns can enter
# the source .zip; anything else (dist/, build output such as
# rustcrypto-wasm/target and rustcrypto-wasm/pkg, keys, screenshots, editor or
# OS litter, files added in the future) is left out by default.
# `*` matches across `/`. Every pattern must match at least one file, so a
# renamed or deleted file fails the build instead of silently shrinking the package.
SOURCE_ALLOW=(
  'LICENSE'
  'NOTICES.md'
  'README.md'
  'docs/*.md'
  'manifests/firefox.json'
  'tools/build.sh'
  'src/*.js'
  'src/*.css'
  'src/*.html'
  'src/*.svg'
  'rustcrypto-wasm/Cargo.toml'
  'rustcrypto-wasm/Cargo.lock'
  'rustcrypto-wasm/LICENSE'
  'rustcrypto-wasm/about.toml'
  'rustcrypto-wasm/entry.js'
  'rustcrypto-wasm/.cargo/config.toml'
  'rustcrypto-wasm/src/*.rs'
)

# Files stored with the executable bit in the source package.
SOURCE_EXEC=(
  'tools/build.sh'
)

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
  # under the repository root, where build outputs are written.
  local real
  real="$(realpath -e -- "$f")"
  case "$real" in
    "$ROOT"/*) ;;
    *)
      echo "error: '$real' is outside the repository root, refusing to remove" >&2
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

# Staging directories are created as "$TMPDIR/agecord-build.XXXXXXXXXX"
# (TMPDIR defaults to /tmp). Removal is only allowed for a real directory that
# is a direct child of that same temp root and carries that prefix.
# No -rf: rejects unsafe paths and symlinks, then uses
# `find -depth -delete` on a path already confirmed to be a real dir.
STAGE_PREFIX="agecord-build"

safe_rm_dir() {
  local dir="$1"
  [[ -n "$dir" && -e "$dir" ]] || return 0
  if [[ -L "$dir" ]]; then
    echo "error: '$dir' is a symlink, refusing to remove" >&2
    exit 1
  fi
  local real tmp_root
  real="$(realpath -e -- "$dir")"
  tmp_root="$(realpath -e -- "${TMPDIR:-/tmp}")"
  if [[ "$(dirname -- "$real")" != "$tmp_root" || "$(basename -- "$real")" != "$STAGE_PREFIX".* ]]; then
    echo "error: '$real' is not a $STAGE_PREFIX.* directory directly under '$tmp_root', refusing to remove" >&2
    exit 1
  fi
  if [[ -d "$dir" ]]; then
    find "$dir" -depth -delete
  else
    echo "error: '$dir' exists but is not a directory, refusing to remove" >&2
    exit 1
  fi
}

# Global (not `local`) so the EXIT trap can see it after the build function returns.
STAGE=""
trap 'safe_rm_dir "$STAGE"' EXIT

make_stage() {
  STAGE="$(mktemp -d "${TMPDIR:-/tmp}/$STAGE_PREFIX.XXXXXXXXXX")"
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

# Copies src/ into DEST using an ALLOWLIST of file types, or only validates it
# when DEST is "-".
#   stage_src DEST|- TARGET
# Only .js .html .css .svg .png files are accepted. Any other file under src/
# (a key, a stray build artifact, OS litter, a new file type nobody vetted) is
# an error rather than being copied. Symlinks are rejected. For TARGET=firefox
# the PNG icon is skipped because only the Chromium manifest uses it.
stage_src() {
  local dest="$1" target="$2"
  python3 - "$SRC_DIR" "$dest" "$target" <<'PYEOF'
import os
import shutil
import sys

src, dest, target = sys.argv[1:]
ALLOWED_EXT = {".js", ".html", ".css", ".svg", ".png"}
SKIP = {"firefox": {"assets/agecord-512.png"}}.get(target, set())

bad = []
files = []
for dirpath, dirnames, filenames in os.walk(src):  # followlinks=False
    dirnames.sort()
    for d in dirnames:
        if os.path.islink(os.path.join(dirpath, d)):
            bad.append(f"{os.path.join(dirpath, d)} (symlink)")
    for name in sorted(filenames):
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, src).replace(os.sep, "/")
        if os.path.islink(path) or not os.path.isfile(path):
            bad.append(f"{path} (not a regular file)")
        elif os.path.splitext(name)[1] not in ALLOWED_EXT:
            bad.append(f"{path} (file type not in allowlist)")
        elif rel not in SKIP:
            files.append((path, rel))

if bad:
    print("error: refusing to package; unexpected entries under src/:", file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    print("Remove them, or extend ALLOWED_EXT in build.sh's stage_src after review.", file=sys.stderr)
    sys.exit(1)

if dest != "-":
    for path, rel in files:
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(path, out)
PYEOF
}

# Writes a reproducible zip from an ALLOWLIST.
#   zip_files OUT ROOT --allow=PATTERN [--allow=PATTERN ...] [--exec=ARCNAME ...]
# * Only files under ROOT whose relative path matches an --allow pattern are
#   added (fnmatch, case-sensitive, `*` crosses `/`). Every pattern must match
#   at least one file.
# * Reproducible: entries sorted by name, timestamps fixed at 1980-01-01,
#   fixed permissions (0644, or 0755 for --exec names), fixed create_system,
#   no extra fields, deflate level 9. Nothing depends on mtimes, umask,
#   directory order or the checkout path.
# * Fail closed on key material: refuses the whole build if any selected file
#   has a .pem name, or contains PEM armor ("-----BEGIN <label>-----") whatever
#   its name or extension. Nothing is written in that case.
# Keep the writer and the PEM guard in sync with tools/crx3/crx3.py.
zip_files() {
  local out="$1" root="$2"
  shift 2
  safe_rm_file "$out"
  python3 - "$out" "$root" "$@" <<'PYEOF'
import fnmatch
import os
import re
import stat
import sys
import zipfile

out, root, *rest = sys.argv[1:]

allow, exec_names = [], set()
for arg in rest:
    if arg.startswith("--allow="):
        allow.append(arg[len("--allow="):])
    elif arg.startswith("--exec="):
        exec_names.add(arg[len("--exec="):])
    else:
        sys.exit(f"error: unknown argument {arg!r}")
if not allow:
    sys.exit("error: no --allow patterns given; refusing to zip everything")

FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # earliest date the zip format can store
PEM_ARMOR = re.compile(rb"-----BEGIN [A-Z0-9][A-Z0-9 ]*-----")

def pem_problem(rel, data):
    if rel.lower().endswith(".pem"):
        return "has a .pem name"
    m = PEM_ARMOR.search(data)
    if m:
        return f"contains PEM armor ({m.group(0).decode()})"
    return None

candidates = []
for dirpath, dirnames, filenames in os.walk(root):  # followlinks=False
    for name in filenames:
        path = os.path.join(dirpath, name)
        candidates.append((os.path.relpath(path, root).replace(os.sep, "/"), path))

used = set()
selected = []
for rel, path in candidates:
    hits = [p for p in allow if fnmatch.fnmatchcase(rel, p)]
    if not hits:
        continue
    used.update(hits)
    if os.path.islink(path) or not os.path.isfile(path):
        sys.exit(f"error: '{rel}' is not a regular file; refusing to package it")
    selected.append((rel, path))

unused = [p for p in allow if p not in used]
if unused:
    sys.exit("error: allowlist pattern(s) matched no file: " + ", ".join(unused))

selected.sort(key=lambda t: t[0])

payload = []
for rel, path in selected:
    with open(path, "rb") as f:
        data = f.read()
    problem = pem_problem(rel, data)
    if problem:
        sys.exit(f"error: '{rel}' {problem}; refusing to package key material")
    payload.append((rel, data))

missing_exec = exec_names - {rel for rel, _ in payload}
if missing_exec:
    sys.exit("error: --exec name(s) not in archive: " + ", ".join(sorted(missing_exec)))

tmp = out + ".partial"
try:
    with zipfile.ZipFile(tmp, "w") as zf:
        for rel, data in payload:
            zi = zipfile.ZipInfo(rel, FIXED_DATE)
            zi.create_system = 3  # Unix, regardless of the host OS
            mode = 0o755 if rel in exec_names else 0o644
            zi.external_attr = (stat.S_IFREG | mode) << 16
            zf.writestr(zi, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    os.replace(tmp, out)
finally:
    if os.path.exists(tmp):
        os.unlink(tmp)
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
    --log-override:empty-import-meta=silent \
    --banner:js="$banner" \
    --outfile="$stage/content/content.js"

  rm -f -- "$stage/content/emoji_map.js" \
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

  make_stage

  echo "==> [chromium] Staging $SRC_DIR/ (allowlisted file types)..."
  stage_src "$STAGE" chromium

  echo "==> [chromium] Installing $manifest as manifest.json..."
  cp -- "$manifest" "$STAGE/manifest.json"

  echo "==> [chromium] Bundling content script (IIFE)..."
  bundle_content "$STAGE"

  echo "==> [chromium] Packing extension as CRX3..."
  if [[ ! -f "$pem_file" ]]; then
    echo "    No private key found at $pem_file — crx3.py will generate one there (mode 0600)."
    echo "    Keep the generated .pem safe: reusing it keeps the extension ID stable."
  fi
  python3 "$crx3_py" "$STAGE" -o "$out_crx" -p "$pem_file"

  echo "==> [chromium] Done: $out_crx"
}

build_firefox() {
  local manifest="$MANIFEST_DIR/firefox.json"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_xpi="$DIST_DIR/agecord-${version}.xpi"

  make_stage

  echo "==> [firefox] Staging $SRC_DIR/ (allowlisted file types)..."
  # The PNG icon is only used by the Chromium manifest, so it is not staged.
  stage_src "$STAGE" firefox
  cp -- "$manifest" "$STAGE/manifest.json"

  echo "==> [firefox] Bundling content script (IIFE)..."
  bundle_content "$STAGE"

  echo "==> [firefox] Zipping staged tree..."
  zip_files "$out_xpi" "$STAGE" --allow='*'

  echo "==> [firefox] Done: $out_xpi"
}

# The source package keeps the repository layout and carries everything a reviewer
# needs to reproduce the build: src/, rustcrypto-wasm/ with its build steps in
# docs/, and this script. It is built from the SOURCE_ALLOW list above, so
# nothing outside that list can end up in it. Chromium-only files are not listed.
build_source() {
  local manifest="$MANIFEST_DIR/firefox.json"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_zip="$DIST_DIR/agecord-${version}.zip"

  # The source package must be able to rebuild what the extension packages ship,
  # so src/ gets the same file-type check as the extension builds.
  stage_src - source

  local args=() p
  for p in "${SOURCE_ALLOW[@]}"; do args+=("--allow=$p"); done
  for p in "${SOURCE_EXEC[@]}";  do args+=("--exec=$p");  done

  echo "==> [source] Zipping allowlisted source files..."
  zip_files "$out_zip" . "${args[@]}"

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
