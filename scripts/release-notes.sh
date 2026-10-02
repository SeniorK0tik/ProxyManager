#!/usr/bin/env bash
# Checks that a release tag matches the workspace version and writes that version's
# CHANGELOG.md section (without the heading) to the output file.
#
#   scripts/release-notes.sh v0.1.0 release-notes.md
set -euo pipefail

TAG="${1:?usage: release-notes.sh <tag> [output] [changelog]}"
OUT="${2:-/dev/stdout}"
CHANGELOG="${3:-CHANGELOG.md}"
VERSION="${TAG#v}"

CARGO_VERSION="$(grep -m1 -E '^version = "' Cargo.toml | cut -d'"' -f2)"
if [ "$VERSION" != "$CARGO_VERSION" ]; then
    echo "Tag $TAG does not match the workspace version $CARGO_VERSION in Cargo.toml" >&2
    exit 1
fi

# Lines between "## [VERSION]" and the next "## [" heading or the link references,
# with leading and trailing blank lines removed.
NOTES="$(awk -v ver="$VERSION" '
    index($0, "## [") == 1 { if (found) exit; if (index($0, "## [" ver "]") == 1) { found = 1; next } }
    /^\[[^]]+\]: / { if (found) exit }
    found {
        if ($0 ~ /^[[:space:]]*$/) { if (started) blank++; next }
        while (blank > 0) { print ""; blank-- }
        started = 1
        print
    }
' "$CHANGELOG")"

if [ -z "$NOTES" ]; then
    echo "$CHANGELOG has no notes for version $VERSION" >&2
    exit 1
fi
printf '%s\n' "$NOTES" > "$OUT"
