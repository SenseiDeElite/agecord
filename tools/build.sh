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

# FILE ALLOWLIST. Every packaged file is listed explicitly; no pattern/extension selection.
# Unlisted files under src/ or missing listed files both fail the build, preventing silent package changes.

# Paths in SRC_* are relative to src/.
# SRC_SHARED -> .crx, .xpi, source .zip (content/content.js is bundled in extensions, original in source).
# SRC_CHROMIUM_ONLY -> .crx only (Chromium cannot use the SVG icon).
# SRC_SOURCE_ONLY -> source .zip only (inlined into content.js by esbuild).
SRC_SHARED=(
  'assets/agecord-512.svg'
  'background/background.js'
  'content/cdn-bridge.html'
  'content/cdn-bridge.js'
  'content/content.css'
  'content/content.js'
  'content/file-crypto-worker.js'
  'content/upload-interceptor.js'
  'lib/age.min.js'
  'lib/rustcrypto-wasm.min.js'
  'popup/crypto-worker.js'
  'popup/import-helper.html'
  'popup/import-helper.js'
  'popup/licenses.html'
  'popup/popup.css'
  'popup/popup.html'
  'popup/popup.js'
)
SRC_CHROMIUM_ONLY=(
  'assets/agecord-512.png'
)
SRC_SOURCE_ONLY=(
  'content/emoji_map.js'
  'content/highlight_map.js'
)

# Files in the source .zip that are not under src/ (paths relative to the repo root).
SOURCE_EXTRA=(
  'LICENSE'
  'NOTICES.md'
  'README.md'
  'docs/DEVELOPMENT.md'
  'docs/TROUBLESHOOTING.md'
  'docs/USAGE.md'
  'manifests/firefox.json'
  'tools/build.sh'
  'rustcrypto-wasm/.cargo/config.toml'
  'rustcrypto-wasm/Cargo.lock'
  'rustcrypto-wasm/Cargo.toml'
  'rustcrypto-wasm/LICENSE'
  'rustcrypto-wasm/about.toml'
  'rustcrypto-wasm/entry.js'
  'rustcrypto-wasm/src/lib.rs'
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

# Staging dirs are "$TMPDIR/agecord-build.XXXXXXXXXX" (TMPDIR defaults to /tmp).
# Cleanup requires a real directory directly under that temp root with that prefix.
# No -rf: validate path and reject symlinks, then run `find -depth -delete` on the confirmed dir.
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

# Validates src/ against the allowlist, then copies TARGET files to DEST unless DEST is "-".
#   stage_src DEST|- TARGET    TARGET: chromium | firefox | source
# Every src/ file must be listed and exist; unlisted files or symlinks fail.
# chromium stages SHARED + CHROMIUM_ONLY; firefox stages SHARED; source stages nothing.
stage_src() {
  local dest="$1" target="$2" f
  local -a args=()
  for f in "${SRC_SHARED[@]}";         do args+=("shared:$f");   done
  for f in "${SRC_CHROMIUM_ONLY[@]}";  do args+=("chromium:$f"); done
  for f in "${SRC_SOURCE_ONLY[@]}";    do args+=("source:$f");   done
  python3 - "$SRC_DIR" "$dest" "$target" "${args[@]}" <<'PYEOF'
import os
import shutil
import sys

src, dest, target, *entries = sys.argv[1:]

groups = {"shared": [], "chromium": [], "source": []}
for entry in entries:
    group, rel = entry.split(":", 1)
    groups[group].append(rel)
listed = [rel for rels in groups.values() for rel in rels]
if len(set(listed)) != len(listed):
    sys.exit("error: a file is listed more than once in the allowlist arrays")

bad = []
for rel in listed:
    if os.path.isabs(rel) or ".." in rel.split("/"):
        sys.exit(f"error: unsafe allowlist path {rel!r}")

on_disk = set()
for dirpath, dirnames, filenames in os.walk(src):  # followlinks=False
    for d in dirnames:
        if os.path.islink(os.path.join(dirpath, d)):
            bad.append(f"{os.path.join(dirpath, d)} (symlink)")
    for name in filenames:
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, src).replace(os.sep, "/")
        if os.path.islink(path) or not os.path.isfile(path):
            bad.append(f"{path} (not a regular file)")
        else:
            on_disk.add(rel)
            if rel not in listed:
                bad.append(f"{path} (not in the file allowlist)")
for rel in sorted(set(listed) - on_disk):
    bad.append(f"{os.path.join(src, rel)} (listed in build.sh but missing)")

if bad:
    print("error: src/ does not match the file allowlist in build.sh:", file=sys.stderr)
    for b in sorted(bad):
        print(f"  {b}", file=sys.stderr)
    print("Remove the file, or add/remove its line in build.sh after review.", file=sys.stderr)
    sys.exit(1)

if dest != "-":
    want = {"chromium": groups["shared"] + groups["chromium"],
            "firefox":  groups["shared"]}.get(target, [])
    for rel in want:
        out = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        shutil.copyfile(os.path.join(src, rel), out)
PYEOF
}

# Prints the exact file list of an extension package, one path per line.
ext_files() {
  printf '%s\n' manifest.json "${SRC_SHARED[@]}"
  if [[ "$1" == chromium ]]; then printf '%s\n' "${SRC_CHROMIUM_ONLY[@]}"; fi
}

# Fails unless DIR contains exactly the given files (no extras, none missing, no symlinks).
#   check_tree DIR FILE...
check_tree() {
  python3 - "$@" <<'PYEOF'
import os
import sys

root, *expected = sys.argv[1:]
expected = set(expected)
found = set()
bad = []
for dirpath, dirnames, filenames in os.walk(root):
    for name in filenames:
        path = os.path.join(dirpath, name)
        rel = os.path.relpath(path, root).replace(os.sep, "/")
        if os.path.islink(path) or not os.path.isfile(path):
            bad.append(f"{rel} (not a regular file)")
        else:
            found.add(rel)
bad += [f"{r} (unexpected)" for r in sorted(found - expected)]
bad += [f"{r} (missing)" for r in sorted(expected - found)]
if bad:
    print("error: staged package does not match the file allowlist:", file=sys.stderr)
    for b in bad:
        print(f"  {b}", file=sys.stderr)
    sys.exit(1)
PYEOF
}

# Writes a reproducible zip containing exactly the named files.
#   zip_files OUT ROOT --file=RELPATH [--file=RELPATH ...] [--exec=RELPATH ...]
# Each --file is a literal path under ROOT; missing/non-regular files fail, and nothing else is read.
# Entries are sorted, timestamped 1980-01-01, given fixed permissions/create_system/no extra fields,
# and deflated at level 9, independent of mtimes, umask, directory order, or checkout path.
# Refuses the entire build if any filename ends in .pem (case-insensitive).
# Keep in sync with tools/crx3/crx3.py.
zip_files() {
  local out="$1" root="$2"
  shift 2
  safe_rm_file "$out"
  python3 - "$out" "$root" "$@" <<'PYEOF'
import os
import stat
import sys
import zipfile

out, root, *rest = sys.argv[1:]

files, exec_names = [], set()
for arg in rest:
    if arg.startswith("--file="):
        files.append(arg[len("--file="):])
    elif arg.startswith("--exec="):
        exec_names.add(arg[len("--exec="):])
    else:
        sys.exit(f"error: unknown argument {arg!r}")
if not files:
    sys.exit("error: no --file entries given; refusing to build an empty or open-ended archive")
if len(set(files)) != len(files):
    sys.exit("error: a file is listed more than once")

FIXED_DATE = (1980, 1, 1, 0, 0, 0)  # earliest date the zip format can store

payload = []
for rel in sorted(files):
    if os.path.isabs(rel) or ".." in rel.split("/"):
        sys.exit(f"error: unsafe path {rel!r}")
    path = os.path.join(root, rel)
    if os.path.islink(path) or not os.path.isfile(path):
        sys.exit(f"error: listed file '{rel}' is missing or not a regular file")
    if rel.lower().endswith(".pem"):
        sys.exit(f"error: '{rel}' has a .pem extension; refusing to package it")
    with open(path, "rb") as f:
        payload.append((rel, f.read()))

missing_exec = exec_names - set(files)
if missing_exec:
    sys.exit("error: --exec name(s) not in the file list: " + ", ".join(sorted(missing_exec)))

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

# Bundles the content script as a classic IIFE in STAGE.
#   bundle_content STAGE
# esbuild reads content.js, emoji_map.js and highlight_map.js from src/
# and writes $STAGE/content/content.js. Inlined maps are never staged; workers and popup/*
# remain untouched ES modules.

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

  echo "==> [chromium] Staging allowlisted files from $SRC_DIR/..."
  stage_src "$STAGE" chromium

  echo "==> [chromium] Installing $manifest as manifest.json..."
  cp -- "$manifest" "$STAGE/manifest.json"

  echo "==> [chromium] Bundling content script (IIFE)..."
  bundle_content "$STAGE"

  local -a files
  mapfile -t files < <(ext_files chromium)
  check_tree "$STAGE" "${files[@]}"

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

  echo "==> [firefox] Staging allowlisted files from $SRC_DIR/..."
  stage_src "$STAGE" firefox
  cp -- "$manifest" "$STAGE/manifest.json"

  echo "==> [firefox] Bundling content script (IIFE)..."
  bundle_content "$STAGE"

  local -a files args=()
  mapfile -t files < <(ext_files firefox)
  check_tree "$STAGE" "${files[@]}"

  echo "==> [firefox] Zipping staged tree..."
  local f
  for f in "${files[@]}"; do args+=("--file=$f"); done
  zip_files "$out_xpi" "$STAGE" "${args[@]}"

  echo "==> [firefox] Done: $out_xpi"
}

# Source package preserves the repository layout and includes everything needed to reproduce the build:
# src/, rustcrypto-wasm/ with build steps in docs/, and this script.
# Contains exactly SRC_SHARED + SRC_SOURCE_ONLY + SOURCE_EXTRA, and nothing else.
build_source() {
  local manifest="$MANIFEST_DIR/firefox.json"
  check_src

  local version
  version="$(get_manifest_version "$manifest")"
  mkdir -p -- "$DIST_DIR"
  local out_zip="$DIST_DIR/agecord-${version}.zip"

  # The source package must be able to rebuild what the extension packages ship,
  # so src/ is checked against the same allowlist.
  stage_src - source

  local -a args=()
  local f
  for f in "${SRC_SHARED[@]}" "${SRC_SOURCE_ONLY[@]}"; do args+=("--file=$SRC_DIR/$f"); done
  for f in "${SOURCE_EXTRA[@]}"; do args+=("--file=$f"); done
  for f in "${SOURCE_EXEC[@]}";  do args+=("--exec=$f"); done

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
