#!/usr/bin/env bash
# Checks that HEAD is the release commit for a tag and that every version site carries its version.
#
#     .github/scripts/check-release.sh v0.5.6
set -euo pipefail
tag=$1 version=${1#v}
core=${version%%-*}
subject=$(git log -1 --format=%s)
if [[ ! $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$ ]]; then
    echo "check-release: a release tag is exactly 'vX.Y.Z' or 'vX.Y.Z-rc.N', got '$tag'"
    exit 1
fi
if [ "$subject" != "Release: $tag" ]; then
    echo "check-release: $tag must sit on 'Release: $tag', but HEAD is '$subject'"
    exit 1
fi
stale=""
[ "$(cat VERSION)" = "$version" ] || stale="$stale VERSION"
# CMake's `project(VERSION)` and the C macros take numbers only, so a candidate keeps its core there.
grep -qE "^[[:space:]]+VERSION ${core//./\\.}$" CMakeLists.txt || stale="$stale CMakeLists.txt"
header=$(sed -nE 's/^#define UCALL_VERSION_(MAJOR|MINOR|PATCH) ([0-9]+)$/\2/p' include/ucall/ucall.h | paste -sd. -)
[ "$header" = "$core" ] || stale="$stale include/ucall/ucall.h"
grep -qxF "version: $version" CITATION.cff || stale="$stale CITATION.cff"
if [ -n "$stale" ]; then
    echo "check-release: these files don't carry $version:$stale"
    exit 1
fi
