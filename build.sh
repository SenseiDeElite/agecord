#!/usr/bin/env bash

# build.sh – packages discord-age-encryption into a .crx, .xpi, or source .zip

set -euo pipefail

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

# Paths excluded from every target's output: this script itself, the
# crx3/ dir (crx3.py plus its LICENSE), the signing key, and all three
# possible output artifact names.
common_excludes() {
  printf '%s\n' \
    "$(basename -- "$0")" \
    crx3 \
    discord-age-encryption.pem \
    discord-age-encryption.crx \
    discord-age-encryption.xpi \
    discord-age-encryption.zip
}

chromium_only_excludes() {
  printf '%s\n' \
    icons/icon-512.svg \
    manifest-firefox.json \
    README.md \
    DEVELOPMENT.md \
    updates.json \
    updates.xml \
    policies.json \
    TROUBLESHOOTING.md \
    NOTICES.md \
    rustcrypto-wasm
}

firefox_only_excludes() {
  printf '%s\n' \
    manifest-chromium.json \
    DEVELOPMENT.md \
    README.md \
    updates.json \
    updates.xml \
    icons/icon-128.png \
    policies.json \
    TROUBLESHOOTING.md \
    NOTICES.md \
    rustcrypto-wasm
}

# Reviewers need the wasm source plus the steps to reproduce the build.
source_only_excludes() {
  printf '%s\n' \
    icons/icon-128.png \
    manifest-chromium.json \
    policies.json \
    README.md \
    TROUBLESHOOTING.md \
    updates.xml \
    NOTICES.md
}

# Excludes are pruned during the directory walk (never descended into)
# rather than matched per-file, so "rustcrypto-wasm" alone is enough.
# Optional --rename=SRC:ARCNAME args zip SRC in under ARCNAME instead of
# its real path, with no file on disk touched.
zip_dir_contents() {
  local out="$1"
  shift
  safe_rm_file "$out"
  python3 - "$out" "$@" <<'PYEOF'
import fnmatch
import os
import sys
import zipfile

out, *rest = sys.argv[1:]

excludes = []
renames = {}
for arg in rest:
    if arg.startswith("--rename="):
        src, arcname = arg[len("--rename="):].split(":", 1)
        renames[src] = arcname
    else:
        excludes.append(arg)

def excluded(rel):
    return any(fnmatch.fnmatch(rel, pat) for pat in excludes)

with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    for dirpath, dirnames, filenames in os.walk("."):
        dirnames[:] = [
            d for d in dirnames
            if not excluded(os.path.relpath(os.path.join(dirpath, d), "."))
        ]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, ".")
            if excluded(rel):
                continue
            arcname = renames.get(rel, rel).replace(os.sep, "/")
            zf.write(path, arcname)
PYEOF
}

build_chromium() {
  local crx3_py="crx3/crx3.py"
  local pem_file="discord-age-encryption.pem"
  local out_crx="./discord-age-encryption.crx"
  require_file "$crx3_py" "crx3.py"

  # not `local`: the EXIT trap below runs after this function returns,
  # when a local variable would already be out of scope
  stage="$(mktemp -d)"
  trap 'safe_rm_dir "$stage"' EXIT

  local tar_excludes=()
  local pat
  while IFS= read -r pat; do
    tar_excludes+=(--exclude="./$pat")
  done < <(common_excludes; chromium_only_excludes)

  echo "==> [chromium] Staging a trimmed copy of the extension..."
  tar "${tar_excludes[@]}" -cf - . | tar -xf - -C "$stage"

  echo "==> [chromium] Renaming manifest-chromium.json to manifest.json..."
  mv "$stage/manifest-chromium.json" "$stage/manifest.json"

  echo "==> [chromium] Packing extension as CRX3..."
  if [[ ! -f "$pem_file" ]]; then
    echo "    No private key found at $pem_file — crx3.py will generate one there."
    echo "    Keep the generated .pem safe: reusing it keeps the extension ID stable."
  fi
  python3 "$crx3_py" "$stage" -o "$out_crx" -p "$pem_file"

  echo "==> [chromium] Done: $out_crx"
}

build_firefox() {
  require_file manifest-firefox.json "manifest-firefox.json"

  local out_xpi="./discord-age-encryption.xpi"
  local excludes
  mapfile -t excludes < <(common_excludes; firefox_only_excludes)
  echo "==> [firefox] Zipping extension (manifest-firefox.json as manifest.json)..."
  zip_dir_contents "$out_xpi" \
    "${excludes[@]}" \
    --rename=manifest-firefox.json:manifest.json

  echo "==> [firefox] Done: $out_xpi"
}

build_source() {
  require_file manifest-firefox.json "manifest-firefox.json"

  local out_zip="./discord-age-encryption.zip"
  local excludes
  mapfile -t excludes < <(common_excludes; source_only_excludes)
  echo "==> [source] Zipping source (manifest-firefox.json as manifest.json)..."
  zip_dir_contents "$out_zip" \
    "${excludes[@]}" \
    --rename=manifest-firefox.json:manifest.json

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
