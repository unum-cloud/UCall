#!/usr/bin/env bash
# Checks the CPU class units of `ucall_static`: each defines the network variants of its own class, and none exports a
# StringZilla, NumKong or ForkUnion C kernel, which must stay local to the unit that compiled it with its own targets,
# or the linker would keep one class's copy for every class.
#
# Usage: class_units.sh <nm> <types.h> <object>... (each may be a `;`-separated list, as CMake passes one)
set -euo pipefail
nm_tool=$1 types=$2
shift 2
failures=0 checked=0
objects=()
for listed in "$@"; do
    IFS=';' read -ra split <<< "$listed"
    objects+=("${split[@]}")
done
for object in "${objects[@]}"; do
    case "$object" in
    *variants_*.o | *variants_*.obj) ;;
    *) continue ;;
    esac
    class=${object##*variants_}
    class=${class%%.*}
    checked=$((checked + 1))
    defined=$("$nm_tool" -C --defined-only "$object")
    value=$(sed -nE "s/^[[:space:]]*ucall_cpu_class_${class}_k = ([0-9]+).*/\1/p" "$types")
    if [ -z "$value" ] || ! grep -qF "make_network_variant<(unum::ucall::cpu_class_t)$value," <<< "$defined"; then
        echo "FAILED  $class unit defines no network variant of its class" >&2
        failures=$((failures + 1))
    fi
    exported=$(grep -E ' [TWV] (sz_|nk_|fu_)[a-z0-9_]+\(' <<< "$defined" || true)
    if [ -n "$exported" ]; then
        printf 'FAILED  %s unit exports library kernels:\n%s\n' "$class" "$exported" >&2
        failures=$((failures + 1))
    fi
done
[ "$checked" -gt 0 ] || {
    echo "FAILED  no class unit among the objects" >&2
    exit 1
}
echo "passed  $checked class units"
exit $((failures != 0))
