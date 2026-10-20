#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if [[ $# != 1 || ! "$1" =~ ^[a-f0-9]{64}$ ]]; then
  printf '%s\n' 'usage: build.sh VERIFIED_PUBLIC_MATRIX_LIBRARY_SHA256' >&2; exit 2
fi
"${PYTHON:-python3}" verify_dependencies.py
mkdir -p build
parent=../zero_readback
vendor=../../vendor/mlkem-native
common=../vector_public_matrix
manifest="$PWD/$common/backend.sha256"
library="$common/build/libpublic_matrix.a"
(cd "$vendor" && sha256sum -c "$manifest") > build/backend_verification.log
(cd "$parent" && sha256sum -c crypto_sources.sha256) > build/crypto_sources_verification.log
printf '%s  %s\n' "$1" "$library" | sha256sum -c -
cmp public_matrix.h "$common/public_matrix.h"
flags=(-O3 -fstack-usage -std=c11 -Wall -Wextra -Werror -march=armv8.2-a+crypto
 -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem
 -DMLK_CONFIG_NO_RANDOMIZED_API -DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH
 -DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 -I"$vendor/mlkem" -I"$common" -I"$parent")
gcc "${flags[@]}" joint_harness.c joint_controller.c joint_trace.c \
 "$parent/assisted_expansion.c" "$library" -lm -o build/scar_mlkem
sha256sum joint_harness.c joint_controller.c joint_controller.h deadline_wait.inc \
 causal_policy.inc "$library" build/scar_mlkem
