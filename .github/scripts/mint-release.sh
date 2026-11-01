#!/usr/bin/env bash
# Mints a release: stamps the version everywhere, commits, tags, pushes and publishes the release page.
#
#     .github/scripts/mint-release.sh 1.0.0          # stable
#     .github/scripts/mint-release.sh 1.1.0-rc.1     # candidate, published as a prerelease
set -euo pipefail
version=$1 core=${1%%-*}
branch=$(git branch --show-current)
previous=$(git describe --tags --abbrev=0)
git diff --quiet HEAD || { echo "mint-release: commit or stash your changes first"; exit 1; }

IFS=. read -r major minor patch <<< "$core"
export version core major minor patch
echo "$version" > VERSION
perl -pi -e 's/^([[:space:]]+VERSION )[0-9.]+$/$1$ENV{core}/' CMakeLists.txt
perl -pi -e 's/^(#define UCALL_VERSION_MAJOR )[0-9]+$/$1$ENV{major}/; s/^(#define UCALL_VERSION_MINOR )[0-9]+$/$1$ENV{minor}/; s/^(#define UCALL_VERSION_PATCH )[0-9]+$/$1$ENV{patch}/' c/ucall/types.h
perl -pi -e 's/^version: .+$/version: $ENV{version}/' CITATION.cff
perl -pi -e 's/^(version = ")[^"]+/$1$ENV{version}/' Cargo.toml
git commit -am "Release: v$version"
.github/scripts/check-release.sh "v$version" # catches a missed site even where `core.hooksPath` is unset
git tag -a "v$version" -m "Release: v$version"
git push --atomic origin "$branch" "v$version"

# Candidates never take "Latest", and neither does a patch to an older line.
flags=()
[[ $version == *-rc.* ]] && flags+=(--prerelease --title "Candidate v$version")
[ "$(git tag -l 'v*' --sort=-v:refname | grep -v -- - | head -1)" = "v$version" ] || flags+=(--latest=false)
gh release create "v$version" --verify-tag --notes "$(git log --no-merges --format='- %s (%h)' "$previous..v$version^")" "${flags[@]}"
