#!/usr/bin/env bash
# Mints a release: stamps the version everywhere, commits, tags, pushes and publishes the release page.
#
#     .github/scripts/mint-release.sh 0.5.6          # stable
#     .github/scripts/mint-release.sh 0.6.0-rc.1     # candidate, published as a prerelease
set -euo pipefail
version=$1 core=${1%%-*}
branch=$(git branch --show-current)
previous=$(git describe --tags --abbrev=0)
git diff --quiet HEAD || { echo "mint-release: commit or stash your changes first"; exit 1; }

export version core
echo "$version" > VERSION
perl -pi -e 's/^(\s+VERSION )[0-9.]+$/$1$ENV{core}/' CMakeLists.txt
perl -pi -e 'BEGIN { ($major, $minor, $patch) = split /\./, $ENV{core} } s/^(#define UCALL_VERSION_MAJOR )\d+$/$1$major/; s/^(#define UCALL_VERSION_MINOR )\d+$/$1$minor/; s/^(#define UCALL_VERSION_PATCH )\d+$/$1$patch/' include/ucall/ucall.h
perl -pi -e 's/^version: .+$/version: $ENV{version}/' CITATION.cff
git commit -am "Release: v$version"
.github/scripts/check-release.sh "v$version" # no hooks here, so this is what catches a missed site
git tag -a "v$version" -m "Release: v$version"
git push --atomic origin "$branch" "v$version"

# Candidates never take "Latest", and neither does a patch to an older line.
flags=()
[[ $version == *-rc.* ]] && flags+=(--prerelease --title "Candidate v$version")
[ "$(git tag -l 'v*' --sort=-v:refname | grep -v -- - | head -1)" = "v$version" ] || flags+=(--latest=false)
gh release create "v$version" --verify-tag --notes "$(git log --no-merges --format='- %s (%h)' "$previous..v$version^")" "${flags[@]}"
