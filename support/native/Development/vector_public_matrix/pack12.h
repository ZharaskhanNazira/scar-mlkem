/* Lossless12-bit public coefficient codec using AArch64 NEON.
 * Same internal byte representation and valid domain as the scalar parent.
 * Public buffers must be disjoint. No key/wire-format or lattice change.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#ifndef SCAR_PACK12_H
#define SCAR_PACK12_H
#include <assert.h>
#include <stdint.h>
#include <arm_neon.h>
#if !defined(__aarch64__) || defined(NDEBUG)
#error AArch64 and active range assertions are required.
#endif
static inline int scar_pack12_coefficients_valid(const int16_t in[256])
{
    uint16x8_t invalid = vdupq_n_u16(0);
    const uint16x8_t limit = vdupq_n_u16(3329);
    /* Negative int16 values reinterpret above32767, so unsigned>=3329
     * rejects both negative and too-large coefficients. Every lane is read. */
    for (unsigned j = 0; j < 256; j += 8)
        invalid = vorrq_u16(invalid, vcgeq_u16(vreinterpretq_u16_s16(vld1q_s16(in+j)), limit));
    return vmaxvq_u16(invalid) == 0;
}
static inline void scar_pack12_poly(uint8_t out[384], const int16_t in[256])
{
    /* Retain the complete domain check; aggregate it before any output store. */
    assert(scar_pack12_coefficients_valid(in));
    for (unsigned j = 0; j < 16; j++) {
        int16x8x2_t pair = vld2q_s16(in + 16*j);
        uint16x8_t a = vreinterpretq_u16_s16(pair.val[0]);
        uint16x8_t b = vreinterpretq_u16_s16(pair.val[1]);
        uint8x8x3_t bytes;
        bytes.val[0] = vmovn_u16(a);
        bytes.val[1] = vmovn_u16(vorrq_u16(vshrq_n_u16(a,8),vshlq_n_u16(b,4)));
        bytes.val[2] = vmovn_u16(vshrq_n_u16(b,4));
        vst3_u8(out + 24*j, bytes);
    }
}
static inline void scar_unpack12_poly(int16_t out[256], const uint8_t in[384])
{
    for (unsigned j = 0; j < 16; j++) {
        uint8x8x3_t bytes = vld3_u8(in + 24*j);
        uint16x8_t middle = vmovl_u8(bytes.val[1]);
        int16x8x2_t pair;
        pair.val[0] = vreinterpretq_s16_u16(vorrq_u16(vmovl_u8(bytes.val[0]),vshlq_n_u16(vandq_u16(middle,vdupq_n_u16(15)),8)));
        pair.val[1] = vreinterpretq_s16_u16(vorrq_u16(vshrq_n_u16(middle,4),vshlq_n_u16(vmovl_u8(bytes.val[2]),4)));
        vst2q_s16(out + 16*j, pair);
    }
}
#endif
