#!/bin/bash
# Generate compile_commands.json for LSP support (like clangd).
#
# Uses the in-kernel gen_compile_commands.py (available since v5.10).
# Its output is filtered to map back from the build-*/ directory to the actual source files.

set -e

die () { echo >&2 "$@"; exit 1; }

[ "$#" -lt 2 ] && die "Usage: $0 <kdir> <build-dir> [output]"

KDIR="$1"
BUILD_DIR="$2"
OUTPUT="${3:-compile_commands.json}"

GEN_COMPILE_COMMANDS="$KDIR/scripts/clang-tools/gen_compile_commands.py"

[ ! -f "$GEN_COMPILE_COMMANDS" ] && die "error: $GEN_COMPILE_COMMANDS not found (kernel too old?)"

if ! command -v jq >/dev/null 2>&1; then
	die "error: jq is required but not installed"
fi

tmpfile=$(mktemp "$OUTPUT.XXXXXX")
trap 'rm -f "$tmpfile"' EXIT

python3 "$GEN_COMPILE_COMMANDS" -d "$BUILD_DIR" -o "$tmpfile"

# strip the build-*/ prefix from all files and directories.
# also, drbd_strings.c is symlinked into the build directory during build, but we want to refer to the actual
# source file in drbd-headers; rewrite that too.
# drbd_buildtag.c only ever exists in the build directory, so stripping the prefix would leave a dangling
# entry; drop it along with the generated .mod.c files.
jq '[ .[]
	| select(.file | test("\\.mod\\.c|/drbd_buildtag\\.c$") | not)
	| .file      |= sub("build-[^/]+/"; "")
	| .directory |= sub("build-[^/]+/?$"; "")
	| .file      |= sub("/drbd_strings\\.c$"; "/drbd-headers/drbd_strings.c")
	| .command   |= sub(" drbd_strings\\.c$"; " drbd-headers/drbd_strings.c")
]' "$tmpfile" > "$OUTPUT"

echo "  GEN     $OUTPUT ($(jq length "$OUTPUT") entries)"
