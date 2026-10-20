/* Experimental shared ML-KEM-768 packed public-matrix primitive. Qualification pending.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#ifndef SCAR_PUBLIC_MATRIX_H
#define SCAR_PUBLIC_MATRIX_H
#include <stddef.h>
#include <stdint.h>

typedef struct ScarPublicMatrix ScarPublicMatrix;
#define SCAR_PUBLIC_ARGUMENT_ERROR (-100)

/* The returned record is created internally, never deserialized. Callers must
 * protect integrity and serialize destruction/invalidation against borrowers.
 * generation must be nonzero and change when the owning context is replaced.
 * Construction uses rho only; this is NOT public-key validation or enrollment.
 * Native pointers/records must never cross process, backend or persistence bounds.
 */
ScarPublicMatrix *scar_public_create(const uint8_t *ek, size_t ek_bytes,
                                     uint64_t generation);
/* Caller-owned arena form: storage must have at least record_bytes() bytes,
 * alignment() alignment and no overlap with ek. Failed argument checks leave
 * storage unchanged. Clear releases no storage; destroy is for create() only.
 */
ScarPublicMatrix *scar_public_init_in_place(void *storage, size_t storage_bytes,
                                           const uint8_t *ek, size_t ek_bytes,
                                           uint64_t generation);
void scar_public_invalidate(ScarPublicMatrix *record);
void scar_public_clear(ScarPublicMatrix *record);
void scar_public_destroy(ScarPublicMatrix *record);
size_t scar_public_record_bytes(void);
size_t scar_public_payload_bytes(void);
size_t scar_public_alignment(void);

/* Explicit lengths reject wrong-size/null input before touching output.
 * All input/output/record allocations must be distinct and non-overlapping.
 * NULL, invalidated, wrong-generation or different-rho records fall back to the
 * unchanged mlkem_dec. A matching record still runs check_sk on EVERY call.
 * used_public is optional and is 1 only after cached reencryption was executed.
 * Corrupted matrix contents are outside the trusted-record contract; a rho tag
 * is NOT authentication. No secret lifetime is changed by this primitive.
 */
int scar_public_dec(uint8_t *ss, size_t ss_bytes,
                    const uint8_t *ct, size_t ct_bytes,
                    const uint8_t *dk, size_t dk_bytes,
                    const ScarPublicMatrix *record, uint64_t generation,
                    int *used_public);
#endif
