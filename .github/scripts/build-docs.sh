#!/usr/bin/env bash
# Writes the symbol bundle unum.cloud renders: each binding's own tool output, or its sources where no tool emits one.
#
#     .github/scripts/build-docs.sh        # → build/ucall_docs_<version>.tar.gz
set -euo pipefail
version=$(cat VERSION)
name=ucall_docs_$version out=build/ucall_docs_$version
# Rustdoc's JSON is unstable, so this pins the toolchain whose format the website reads.
toolchain=${UCALL_RUST_TOOLCHAIN:-beta-2026-10-18}
rm -rf "$out" && mkdir -p "$out"/{doxygen,headers,python,rust,mojo} build/docs-scratch/library

rm -rf build/xml && (cd docs && doxygen conf.dox) && cp -r build/xml/. "$out/doxygen"
git ls-files 'c/ucall/*.h' | xargs cp --parents -t "$out/headers"
griffe dump ucall --search python --no-inspection --docstyle google --full --output "$out/python/ucall.json"
cp python/ucall/lib.pyi "$out/python/"
UCALL_LIBRARY_DIR=$PWD/build/docs-scratch/library RUSTC_BOOTSTRAP=1 \
    cargo +"$toolchain" rustdoc --lib -- -Z unstable-options --output-format json
cp "${CARGO_TARGET_DIR:-target}/doc/ucall.json" "$out/rust/"
mojo doc -o "$out/mojo/ucall.json" mojo/ucall
cp mojo/ucall/__init__.mojo "$out/mojo/"
# griffe, rustdoc, Mojo and Doxygen's body locations hold absolute paths, which would leak the build machine's
# directories.
sed -i "s|$PWD/||g; s|$PWD|.|g; s|$HOME|~|g" "$out/python/ucall.json" "$out/rust/ucall.json" "$out/mojo/ucall.json" \
    "$out"/doxygen/*.xml
printf '{"project":"ucall","version":"%s","commit":"%s"}\n' "$version" "$(git rev-parse HEAD)" > "$out/manifest.json"
tar -czf "build/$name.tar.gz" -C build "$name"
