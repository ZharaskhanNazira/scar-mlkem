#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
vendor=../../vendor/mlkem-native
mkdir -p build
manifest="$PWD/backend.sha256"
(cd "$vendor" && sha256sum -c "$manifest") > build/backend_verification.log
flags=(-O3 -fstack-usage -std=c11 -Wall -Wextra -Werror -march=armv8.2-a+crypto
 -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem
 -DMLK_CONFIG_NO_RANDOMIZED_API -DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH
 -DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 -I"$vendor/mlkem")
gcc "${flags[@]}" -c "$vendor/mlkem/mlkem_native_asm.S" -o build/public_matrix_asm.o
gcc "${flags[@]}" -c public_matrix_backend.c -o build/public_matrix_backend.o
ar rcs build/libpublic_matrix.a build/public_matrix_backend.o build/public_matrix_asm.o
gcc "${flags[@]}" conformance.c build/libpublic_matrix.a -o build/public_matrix_conformance
sha256sum public_matrix.h public_matrix_backend.c pack12.h conformance.c build.sh backend.sha256 \
 build/libpublic_matrix.a build/public_matrix_conformance
