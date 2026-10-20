/* Internal retained-secret representation, not a new ML-KEM key format.
 * FIPS203 Algorithm16: dk = dkPKE || ek || H(ek) || z, k=3.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT */
#ifndef SCAR_SECRET_CORE_H
#define SCAR_SECRET_CORE_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
enum { SCAR_SECRET_CORE_BYTES=1152, SCAR_FULL_DK_BYTES=2400 };
/* All pointers must refer to valid disjoint buffers. These routines do not
 * authenticate enrollment, validate key contents, own memory or erase it.
 * Caller binds all components to the same context/generation and clears all
 * secret storage. Invalid sizes/null pointers cause no output writes. */
static inline int scar_secret_extract(uint8_t *core, size_t core_bytes,
                                      const uint8_t *dk, size_t dk_bytes)
{
    if (!core || !dk || core_bytes!=1152 || dk_bytes!=2400) return -1;
    memcpy(core,dk,1152);
    return 0;
}
static inline int scar_secret_compose(uint8_t *dk, size_t dk_bytes,
                                      const uint8_t *core, size_t core_bytes,
                                      const uint8_t *ek, size_t ek_bytes,
                                      const uint8_t *h, size_t h_bytes,
                                      const uint8_t *z, size_t z_bytes)
{
    if (!dk || !core || !ek || !h || !z || dk_bytes!=2400 ||
        core_bytes!=1152 || ek_bytes!=1184 || h_bytes!=32 || z_bytes!=32)
        return -1;
    memcpy(dk,core,1152);
    memcpy(dk+1152,ek,1184);
    memcpy(dk+2336,h,32);
    memcpy(dk+2368,z,32);
    return 0;
}
#endif
