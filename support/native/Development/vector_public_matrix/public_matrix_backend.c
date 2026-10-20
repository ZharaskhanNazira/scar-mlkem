/* Fixed ARM64/ML-KEM-768 single compilation unit. The backend sources below
 * are included unchanged from the pinned tree. The SCU include list follows
 * mlkem/mlkem_native.c; its macro-cleanup tail is unnecessary in a single build.
 * Original backend: Copyright (c) the mlkem-native project authors.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#include <stdlib.h>
#include <string.h>
#include "src/common.h"
#if MLK_CONFIG_PARAMETER_SET != 768 || MLKEM_K != 3
#error This experiment is restricted to ML-KEM-768.
#endif
#if !defined(MLK_SYS_AARCH64) || !defined(MLK_CONFIG_USE_NATIVE_BACKEND_ARITH) || \
    !defined(MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202)
#error This experiment requires the pinned native ARM64 configuration.
#endif
#if defined(MLK_CONFIG_CUSTOM_ALLOC_FREE) || defined(MLK_CONFIG_KEYGEN_PCT) || \
    defined(MLK_CONFIG_MULTILEVEL_BUILD) || defined(MLK_CONFIG_CONTEXT_PARAMETER) || \
    defined(MLK_CONFIG_FIPS202_CUSTOM_HEADER)
#error Unsupported configuration for this isolated proof of concept.
#endif

#include "src/compress.c"
#include "src/debug.c"
#include "src/indcpa.c"
#include "src/kem.c"
#include "src/poly.c"
#include "src/poly_k.c"
#include "src/sampling.c"
#include "src/verify.c"
#include "src/fips202/fips202.c"
#include "src/fips202/fips202x4.c"
#include "src/fips202/keccakf1600.c"
#include "src/native/aarch64/src/aarch64_zetas.c"
#include "src/native/aarch64/src/rej_uniform_table.c"
#include "src/fips202/native/aarch64/src/keccakf1600_round_constants.c"
#include "public_matrix.h"
#include "pack12.h"

/* Only packed public values. No transformed ephemeral secret or multiplication cache.
 * The layout is private so ordinary callers cannot alter fields independently.
 */
struct ScarPublicMatrix {
    uint8_t packed_at[3][1152] __attribute__((aligned(32)));
    uint8_t rho[32];
    uint64_t generation;
    uint64_t ready;
};
#define SCAR_PUBLIC_READY UINT64_C(0x53434152504b3132)
_Static_assert(sizeof(mlk_poly) == 512, "polynomial payload");
_Static_assert(sizeof(mlk_polyvec) == 1536, "vector payload");
_Static_assert(sizeof(mlk_polymat) == 4608, "matrix payload");
_Static_assert(_Alignof(mlk_polymat) == 32, "matrix alignment");
_Static_assert(sizeof(ScarPublicMatrix) == 3520, "complete public entry");
_Static_assert(_Alignof(ScarPublicMatrix) == 32, "entry alignment");
_Static_assert(MLKEM_INDCCA_SECRETKEYBYTES == 2400, "standard dk length");
_Static_assert(MLKEM_INDCCA_PUBLICKEYBYTES == 1184, "standard ek length");
_Static_assert(MLKEM_INDCCA_CIPHERTEXTBYTES == 1088, "standard ct length");

size_t scar_public_record_bytes(void) { return sizeof(ScarPublicMatrix); }
size_t scar_public_payload_bytes(void) { return 3456; }
size_t scar_public_alignment(void) { return _Alignof(ScarPublicMatrix); }

ScarPublicMatrix *scar_public_init_in_place(void *storage, size_t storage_bytes,
                                           const uint8_t *ek, size_t ek_bytes,
                                           uint64_t generation)
{
    if (storage == NULL || storage_bytes < sizeof(ScarPublicMatrix) ||
        (uintptr_t)storage % _Alignof(ScarPublicMatrix) != 0 ||
        ek == NULL || ek_bytes != 1184 || generation == 0) return NULL;
    ScarPublicMatrix *r = storage;
    memset(r, 0, sizeof(*r));
    memcpy(r->rho, ek + MLKEM_POLYVECBYTES, 32);
    /* Original generator: transpose flag, native NTT order, original cleanup. */
    MLK_CT_TESTING_DECLASSIFY(r->rho, 32);
    mlk_polymat generated;
    mlk_gen_matrix(&generated, r->rho, 1);
    for (unsigned i = 0; i < 3; i++)
        for (unsigned j = 0; j < 3; j++)
            scar_pack12_poly(r->packed_at[i] + 384*j, generated.vec[i].vec[j].coeffs);
    mlk_zeroize(&generated, sizeof(generated));
    r->generation = generation;
    r->ready = SCAR_PUBLIC_READY;
    return r;
}

ScarPublicMatrix *scar_public_create(const uint8_t *ek, size_t ek_bytes,
                                     uint64_t generation)
{
    if (ek == NULL || ek_bytes != 1184 || generation == 0) return NULL;
    void *storage = aligned_alloc(_Alignof(ScarPublicMatrix), sizeof(ScarPublicMatrix));
    if (storage == NULL) return NULL;
    ScarPublicMatrix *r = scar_public_init_in_place(storage, sizeof(ScarPublicMatrix),
                                                    ek, ek_bytes, generation);
    if (r == NULL) free(storage);
    return r;
}

void scar_public_invalidate(ScarPublicMatrix *record)
{
    if (record != NULL) record->ready = 0;
}

void scar_public_clear(ScarPublicMatrix *record)
{
    if (record != NULL) mlk_zeroize(record, sizeof(*record));
}

void scar_public_destroy(ScarPublicMatrix *record)
{
    if (record != NULL) {
        scar_public_clear(record);
        free(record);
    }
}

/* Source correspondence: pinned indcpa.c:mlk_indcpa_enc. Matrix ownership and lossless row decoding differ. The parsed pk and all coin-derived data stay per-call.
 * Default allocation is compile-time enforced above; original MLK_FREE clears
 * the same owned secret buffers. The borrowed packed matrix is never cleared here; the decoded public row is per-call scratch.
 */
static int scar_reencrypt(uint8_t c[1088], const uint8_t m[32],
                          const uint8_t pk[1184], const uint8_t coins[32],
                          const uint8_t packed_at[3][1152])
{
    int ret = 0;
    MLK_ALLOC(seed, uint8_t, MLKEM_SYMBYTES, NULL);
    MLK_ALLOC(sp, mlk_polyvec, 1, NULL);
    MLK_ALLOC(row, mlk_polyvec, 1, NULL);
    MLK_ALLOC(pkpv, mlk_polyvec, 1, NULL);
    MLK_ALLOC(ep, mlk_polyvec, 1, NULL);
    MLK_ALLOC(b, mlk_polyvec, 1, NULL);
    MLK_ALLOC(v, mlk_poly, 1, NULL);
    MLK_ALLOC(k, mlk_poly, 1, NULL);
    MLK_ALLOC(epp, mlk_poly, 1, NULL);
    MLK_ALLOC(sp_cache, mlk_polyvec_mulcache, 1, NULL);

    if (seed == NULL || packed_at == NULL || row == NULL || sp == NULL || pkpv == NULL || ep == NULL ||
        b == NULL || v == NULL || k == NULL || epp == NULL || sp_cache == NULL) {
        ret = MLK_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }

    /* These static pinned helpers are in this SCU, without multilevel suffix. */
    mlk_unpack_pk(pkpv, seed, pk);
    mlk_poly_frommsg(k, m);
    MLK_CT_TESTING_DECLASSIFY(seed, MLKEM_SYMBYTES);
    mlk_enc_getnoise_eta1_eta2(sp, ep, epp, coins);
    mlk_polyvec_ntt(sp);
    mlk_polyvec_mulcache_compute(sp_cache, sp);
    /* Exact native coefficient order; unpack one row immediately before use. */
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = 0; j < 3; j++)
            scar_unpack12_poly(row->vec[j].coeffs, packed_at[i] + 384*j);
        mlk_polyvec_basemul_acc_montgomery_cached(&b->vec[i], row, sp, sp_cache);
    }
    mlk_polyvec_basemul_acc_montgomery_cached(v, pkpv, sp, sp_cache);
    mlk_polyvec_invntt_tomont(b);
    mlk_poly_invntt_tomont(v);
    mlk_polyvec_add(b, ep);
    mlk_poly_add(v, epp);
    mlk_poly_add(v, k);
    mlk_polyvec_reduce(b);
    mlk_poly_reduce(v);
    mlk_pack_ciphertext(c, b, v);

cleanup:
    MLK_FREE(sp_cache, mlk_polyvec_mulcache, 1, NULL);
    MLK_FREE(epp, mlk_poly, 1, NULL);
    MLK_FREE(k, mlk_poly, 1, NULL);
    MLK_FREE(v, mlk_poly, 1, NULL);
    MLK_FREE(b, mlk_polyvec, 1, NULL);
    MLK_FREE(ep, mlk_polyvec, 1, NULL);
    MLK_FREE(pkpv, mlk_polyvec, 1, NULL);
    MLK_FREE(row, mlk_polyvec, 1, NULL);
    MLK_FREE(sp, mlk_polyvec, 1, NULL);
    MLK_FREE(seed, uint8_t, MLKEM_SYMBYTES, NULL);
    return ret;
}

int scar_public_dec(uint8_t *ss, size_t ss_bytes,
                    const uint8_t *ct, size_t ct_bytes,
                    const uint8_t *dk, size_t dk_bytes,
                    const ScarPublicMatrix *record, uint64_t generation,
                    int *used_public)
{
    if (used_public != NULL) *used_public = 0;
    if (ss == NULL || ct == NULL || dk == NULL || ss_bytes != 32 ||
        ct_bytes != 1088 || dk_bytes != 2400) return SCAR_PUBLIC_ARGUMENT_ERROR;
    const uint8_t *pk = dk + MLKEM_INDCPA_SECRETKEYBYTES;
    MLK_CT_TESTING_DECLASSIFY(pk + MLKEM_POLYVECBYTES, 32);
    if (record == NULL || record->ready != SCAR_PUBLIC_READY ||
        generation == 0 || record->generation != generation ||
        memcmp(record->rho, pk + MLKEM_POLYVECBYTES, 32) != 0)
        return mlk_kem_dec(ss, ct, dk, NULL);

    /* Pinned kem.c:mlk_kem_dec, including hash check and implicit rejection. */
    int ret = 0;
    uint8_t fail;
    MLK_ALLOC(buf, uint8_t, 2 * MLKEM_SYMBYTES, NULL);
    MLK_ALLOC(kr, uint8_t, 2 * MLKEM_SYMBYTES, NULL);
    MLK_ALLOC(tmp, uint8_t, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES, NULL);
    if (buf == NULL || kr == NULL || tmp == NULL) {
        ret = MLK_ERR_OUT_OF_MEMORY;
        goto cleanup;
    }
    ret = mlk_kem_check_sk(dk, NULL);
    if (ret != 0) goto cleanup;
    ret = mlk_indcpa_dec(buf, ct, dk, NULL);
    if (ret != 0) goto cleanup;
    mlk_memcpy(buf + 32, dk + 2336, 32);
    mlk_hash_g(kr, buf, 64);
    ret = scar_reencrypt(tmp, buf, pk, kr + 32, record->packed_at);
    if (ret != 0) goto cleanup;
    if (used_public != NULL) *used_public = 1;
    fail = mlk_ct_memcmp(ct, tmp, 1088);
    mlk_memcpy(tmp, dk + 2368, 32);
    mlk_memcpy(tmp + 32, ct, 1088);
    mlk_hash_j(ss, tmp, 1120);
    mlk_ct_cmov_zero(ss, kr, 32, fail);
cleanup:
    MLK_FREE(tmp, uint8_t, MLKEM_SYMBYTES + MLKEM_INDCCA_CIPHERTEXTBYTES, NULL);
    MLK_FREE(kr, uint8_t, 2 * MLKEM_SYMBYTES, NULL);
    MLK_FREE(buf, uint8_t, 2 * MLKEM_SYMBYTES, NULL);
    return ret;
}
