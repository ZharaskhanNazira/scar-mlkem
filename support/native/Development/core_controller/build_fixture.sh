#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
"${PYTHON:-python3}" verify_dependencies.py
mode=${1:-plain}
flags=(-O3 -g -std=c11 -Wall -Wextra -Werror -I../zero_readback)
if [[ $(uname -s) == Darwin ]]; then flags+=(-include ../zero_readback/fixtures/metadata_compat.h); fi
case "$mode" in
 plain) ;;
 sanitize) flags+=(-O1 -fsanitize=address,undefined -fno-omit-frame-pointer);;
 *) exit 2;;
esac
mkdir -p build
for target in admission_metadata sieve_metadata; do
 "${CC:-cc}" "${flags[@]}" "fixtures/$target.c" -lm -o "build/${target}_$mode"
done
"${CC:-cc}" "${flags[@]}" fixtures/control_parity.c fixtures/parent_impl.c -lm -o "build/control_parity_$mode"
printf '%s\n' "built=admission_metadata,sieve_metadata mode=$mode crypto_linked=0"
