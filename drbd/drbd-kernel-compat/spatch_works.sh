#!/bin/sh

for PATCH in "$@"; do
	spatch --very-quiet --parse-cocci "$PATCH" >/dev/null && echo "  COCCISYNTAX  OK  $(basename "$PATCH")" || { echo "  COCCISYNTAX FAIL $(basename "$PATCH")" ; exit 1 ; }
done
