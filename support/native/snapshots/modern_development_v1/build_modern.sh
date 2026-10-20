#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
flags=(-O3 -std=c11 -Wall -Wextra -Werror -march=armv8.2-a+crypto
 -DMLK_CONFIG_PARAMETER_SET=768 -DMLK_CONFIG_NAMESPACE_PREFIX=mlkem
 -DMLK_CONFIG_NO_RANDOMIZED_API -DMLK_CONFIG_USE_NATIVE_BACKEND_ARITH
 -DMLK_CONFIG_USE_NATIVE_BACKEND_FIPS202 -Ivendor/mlkem-native/mlkem)
# A named assembly object avoids a random GCC temporary FILE symbol in the ELF.
gcc "${flags[@]}" -c vendor/mlkem-native/mlkem/mlkem_native_asm.S -o build/modern_mlkem_asm.o
gcc "${flags[@]}" cache_modern.c vendor/mlkem-native/mlkem/mlkem_native.c \
 build/modern_mlkem_asm.o -lm -o build/cache_modern
sha256sum cache_modern.c build_modern.sh policy_support.h model_lr.h model_trees.h build/cache_modern
