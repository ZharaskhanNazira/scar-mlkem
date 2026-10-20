#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
gcc -O3 -std=c11 -Wall -Wextra -Werror -march=armv8.2-a+crypto \
 -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem \
 -DMLK_CONFIG_NO_RANDOMIZED_API -DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH \
 -DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 -Ivendor/mlkem-native/mlkem \
 cache_benchmark.c vendor/mlkem-native/mlkem/mlkem_native.c \
 vendor/mlkem-native/mlkem/mlkem_native_asm.S -lm -o build/cache_benchmark
sha256sum cache_benchmark.c build_cache.sh build/cache_benchmark
