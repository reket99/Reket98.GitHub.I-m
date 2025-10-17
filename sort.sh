#!/usr/bin/env bash
# Portable organizer for macOS (Bash 3.2) and Linux.
# Organizes files (with extensions only) into categories or by extension.
# Scans recursively up to --depth N (default 2).

set -euo pipefail

usage() {
  cat <<EOF
Usage: $0 [options] <target_dir>

Options:
  -n                     Dry run (no changes)
  -r ROOT                Root folder name (default: _sorted)
  -e ext1,ext2           Only include these extensions (comma-separated)
  -x extA,extB           Exclude these extensions (comma-separated)
  --dedupe               Skip duplicates (same hash) in destination
  --log path.csv         Log all moves (src,target,hash,timestamp)
  --undo path.csv        Undo moves recorded in CSV
  --mode class|ext       Organize by category ("class") or by extension ("ext")
  --depth N              Scan depth (default 2)
  -h, --help             Show this help

Examples:
  $0 -n --dedupe /path/folder
  $0 --mode ext --depth 3 /path/folder
  $0 -r _media -e jpg,png,mp4 /path/folder
EOF
}

# Defaults
DRY_RUN=0
ROOT_DIR="_sorted"
INCLUDE_SET=""
EXCLUDE_SET=""
DEDUPE=0
LOG_FILE=""
UNDO_FILE=""
MODE="class"
DEPTH=2

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n) DRY_RUN=1; shift ;;
    -r) ROOT_DIR="$2"; shift 2 ;;
    -e) INCLUDE_SET="$2"; shift 2 ;;
    -x) EXCLUDE_SET="$2"; shift 2 ;;
    --dedupe) DEDUPE=1; shift ;;
    --log) LOG_FILE="$2"; shift 2 ;;
    --undo) UNDO_FILE="$2"; shift 2 ;;
    --mode) MODE="$2"; shift 2 ;;
    --depth) DEPTH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    --) shift; break ;;
    -*)
      echo "Unknown option: $1" >&2; usage; exit 2 ;;
    *) break ;;
  esac
done

# Undo mode
if [[ -n "${UNDO_FILE}" ]]; then
  [[ -f "${UNDO_FILE}" ]] || { echo "Undo file not found: ${UNDO_FILE}" >&2; exit 1; }
  while IFS=',' read -r SRC TGT HASH TS; do
    [[ "$SRC" == "src" && "$TGT" == "target" ]] && continue
    [[ -n "$SRC" && -n "$TGT" ]] || continue
    if [[ -e "$TGT" && ! -e "$SRC" ]]; then
      echo "UNDO: $TGT -> $SRC"
      if [[ $DRY_RUN -eq 0 ]]; then
        mkdir -p -- "$(dirname -- "$SRC")"
        mv -- "$TGT" "$SRC"
      fi
    fi
  done < "$UNDO_FILE"
  echo "Undo complete."
  exit 0
fi

if [[ $# -lt 1 ]]; then echo "Error: <target_dir> required." >&2; usage; exit 1; fi
TARGET_DIR="${1%/}"
[[ -d "$TARGET_DIR" ]] || { echo "Error: '$TARGET_DIR' is not a directory." >&2; exit 1; }

ROOT_PATH="${TARGET_DIR}/${ROOT_DIR}"

# Helpers (Bash 3.2-safe)
to_lower() { tr '[:upper:]' '[:lower:]'; }
prepare_set() { local s="$1"; s="$(echo "$s" | to_lower | tr -d '[:space:]')"; [[ -n "$s" ]] && echo ",$s," || echo ""; }
INCLUDE_STR="$(prepare_set "$INCLUDE_SET")"
EXCLUDE_STR="$(prepare_set "$EXCLUDE_SET")"
in_set() { local ext="$1" set_str="$2"; [[ -n "$set_str" ]] && case "$set_str" in *,"$ext",*) return 0;; esac; return 1; }

file_hash() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$1" | awk '{print $1}'
  elif command -v md5 >/dev/null 2>&1; then md5 -q -- "$1" 2>/dev/null || true
  elif command -v md5sum >/dev/null 2>&1; then md5sum -- "$1" | awk '{print $1}'
  else echo ""; fi
}

normalize_ext() {
  local path="$1" base ext
  base="$(basename -- "$path")"
  case "$base" in .DS_Store|Thumbs.db|._*) echo ""; return ;; esac
  if [[ "$base" != *.* || ( "$base" == .* && "$base" != *.*.* ) ]]; then echo ""; return; fi
  case "$base" in
    *.tar.gz)  ext="tar.gz" ;;
    *.tar.bz2) ext="tar.bz2" ;;
    *.tar.xz)  ext="tar.xz" ;;
    *)         ext="${base##*.}" ;;
  esac
  echo "$ext" | to_lower
}

ext_to_bucket() {
  local ext="$1"
  case "$ext" in
    jpg|jpeg|png|gif|bmp|webp|tif|tiff|svg|ico|icns|heic|heif) echo "images" ;;
    mp4|m4v|mov|avi|mkv|webm|wmv|flv|asf|mpeg|mpg|3gp|ts) echo "videos" ;;
    mp3|m4a|aac|wav|flac|ogg|opus|wma|aiff|aif|mid|midi|caf) echo "audio" ;;
    pdf|txt|rtf|md|doc|docx|odt|epub|mobi|pages) echo "documents" ;;
    xls|xlsx|csv|tsv|ods|numbers) echo "spreadsheets" ;;
    ppt|pptx|key|odp) echo "presentations" ;;
    c|cpp|h|hpp|cs|java|class|kt|swift|rs|go|py|rb|php|sh|ps1|r|js|ts|jsx|tsx|json|yaml|yml|xml|html|css|ini|cfg|conf|env|sql|vue|toml|lua) echo "code" ;;
    zip|7z|rar|tar|gz|tgz|bz2|xz|tar.gz|tar.bz2|tar.xz|dmg|iso|img) echo "archives" ;;
    ttf|otf|woff|woff2|eot) echo "fonts" ;;
    log|eml|evt|evtx) echo "logs" ;;
    exe|msi|apk|ipa|deb|rpm|bin|app|pkg) echo "binaries" ;;
    *) echo "other" ;;
  esac
}

unique_target_path() {
  local dir="$1" base="$2" stem ext counter candidate
  if [[ "$base" == *.* ]]; then stem="${base%.*}"; ext=".${base##*.}"; else stem="$base"; ext=""; fi
  candidate="${dir}/${base}"; counter=1
  while [[ -e "$candidate" ]]; do
    candidate="${dir}/${stem}-${counter}${ext}"
    counter=$((counter + 1))
  done
  printf '%s\n' "$candidate"
}

log_move() {
  local src="$1" tgt="$2" hash="$3"
  [[ -n "$LOG_FILE" ]] || return 0
  if [[ ! -e "$LOG_FILE" ]]; then echo "src,target,hash,timestamp" > "$LOG_FILE"; fi
  local ts; ts="$(date -u +'%Y-%m-%dT%H:%M:%SZ')"
  printf '%s,%s,%s,%s\n' "$src" "$tgt" "$hash" "$ts" >> "$LOG_FILE"
}

should_process_ext() {
  local ext="$1"
  if [[ -n "$INCLUDE_STR" ]]; then in_set "$ext" "$INCLUDE_STR" || return 1; fi
  if [[ -n "$EXCLUDE_STR" ]]; then in_set "$ext" "$EXCLUDE_STR" && return 1; fi
  return 0
}

move_file() {
  local src="$1"
  [[ -f "$src" || -L "$src" ]] || return 0
  case "$src" in "$ROOT_PATH"/*) return 0 ;; esac

  local ext base bucket subdir target h=""
  ext="$(normalize_ext "$src")"
  [[ -n "$ext" ]] || return 0
  should_process_ext "$ext" || return 0

  if [[ "$MODE" == "ext" ]]; then bucket="$ext"; else bucket="$(ext_to_bucket "$ext")"; fi
  subdir="${ROOT_PATH}/${bucket}"
  base="$(basename -- "$src")"
  target="$(unique_target_path "$subdir" "$base")"

  if [[ $DEDUPE -eq 1 ]]; then
    h="$(file_hash "$src")"
    if [[ -n "$h" && -d "$subdir" ]]; then
      shopt -s nullglob
      for f in "$subdir"/*; do
        [[ -f "$f" ]] || continue
        local fh; fh="$(file_hash "$f")"
        if [[ -n "$fh" && "$fh" == "$h" ]]; then
          echo "SKIP (duplicate): $src"
          shopt -u nullglob
          return 0
        fi
      done
      shopt -u nullglob
    fi
  fi

  echo "MOVE: $src -> $target"
  if [[ $DRY_RUN -eq 0 ]]; then
    mkdir -p -- "$subdir"
    mv -- "$src" "$target"
    log_move "$src" "$target" "$h"
  fi
}

# ---------- MAIN ----------
mkdir -p -- "$ROOT_PATH"
shopt -s nullglob dotglob

# Dynamically build pattern list up to --depth N
PATTERNS=( )
for ((i=1; i<=DEPTH; i++)); do
  pattern="$TARGET_DIR"
  for ((j=1; j<=i; j++)); do pattern="$pattern/*"; done
  PATTERNS+=( "$pattern" )
done

for pattern in "${PATTERNS[@]}"; do
  for path in $pattern; do
    [[ -e "$path" ]] || continue
    move_file "$path"
  done
done

shopt -u nullglob dotglob
echo "✅ Done. Organized under: $ROOT_PATH (mode: $MODE, depth: $DEPTH)"

