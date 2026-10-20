/* Functional development checks only; never emits secret material or hashes
 * derived from it. Official vector input is already-public test material.
 * Harness lifecycle/parser conventions follow assisted_expansion/benchmark.c.
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/resource.h>
#include <unistd.h>
#include "mlkem_native.h"
#include "src/common.h"
#include "src/symmetric.h"
#include "src/verify.h"
#include "public_matrix.h"

typedef struct {
    uint8_t seed[64], coins[32], ek[1184], alternate_ek[1184];
    uint8_t dk[2400], alternate_dk[2400], expected_dk[2400];
    uint8_t ct[1088], changed_ct[1088], expected_ct[1088];
    uint8_t shared[32], expected_shared[32], ordinary[32], cached[32];
    uint8_t rejection_input[1120], rejection[32];
    uint8_t public_snapshot[3520];
    char line[16384];
} Arena;
static Arena *a;
static ScarPublicMatrix *record, *other;
/* Untyped caller-owned storage exercises in-place construction without aliasing
 * a declared character array as a struct. Public bytes do not need mlock. */
static void *placement;
static uint64_t checks;

static void cleanup(void)
{
    scar_public_destroy(record); record = NULL;
    scar_public_destroy(other); other = NULL;
    if (placement != NULL) { explicit_bzero(placement, 3520); free(placement); placement = NULL; }
    if (a != NULL) {
        explicit_bzero(a, sizeof(*a));
        (void)munlock(a, sizeof(*a));
        (void)munmap(a, sizeof(*a)); a = NULL;
    }
}

static void require(int good, const char *stage)
{
    if (!good) {
        fprintf(stderr, "public_matrix_failed stage=%s errno=%d\n", stage, errno);
        exit(EXIT_FAILURE);
    }
    checks++;
}

static void setup(void)
{
    struct rlimit limit = {0, 0};
    require(setrlimit(RLIMIT_CORE, &limit) == 0, "disable_core");
    require(prctl(PR_SET_DUMPABLE, 0) == 0, "disable_dumpable");
    require(atexit(cleanup) == 0, "register_cleanup");
    void *p = mmap(NULL, sizeof(*a), PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    require(p != MAP_FAILED, "map_arena"); a = p;
    require(mlock(a, sizeof(*a)) == 0, "lock_arena");
    require(madvise(a, sizeof(*a), MADV_DONTDUMP) == 0, "exclude_dump");
    require(scar_public_record_bytes() == 3520 && scar_public_payload_bytes() == 3456 &&
            scar_public_alignment() == 32, "native_sizes");
    placement = aligned_alloc(32, 3520);
    require(placement != NULL, "allocate_caller_owned_storage");
}

static void entropy(uint8_t *out, size_t bytes)
{
    while (bytes != 0) {
        ssize_t n = getrandom(out, bytes, 0);
        if (n < 0 && errno == EINTR) continue;
        require(n > 0, "system_entropy");
        out += (size_t)n; bytes -= (size_t)n;
    }
}

/* Error paths must match both status and unchanged-output behavior. */
static int compare_dec(const uint8_t *dk, const uint8_t *ct,
                        const ScarPublicMatrix *r, uint64_t generation,
                        int expected_used)
{
    int used = -1;
    memset(a->ordinary, 0xa5, 32); memset(a->cached, 0xa5, 32);
    int normal = mlkem_dec(a->ordinary, ct, dk);
    int experimental = scar_public_dec(a->cached, 32, ct, 1088, dk, 2400,
                                       r, generation, &used);
    require(normal == experimental, "same_return_code");
    require(memcmp(a->ordinary, a->cached, 32) == 0, "same_output_bytes");
    require(used == expected_used, "expected_cache_path");
    return normal;
}

static void set_rejection(const uint8_t *dk, const uint8_t *ct)
{
    memcpy(a->rejection_input, dk + 2368, 32);
    memcpy(a->rejection_input + 32, ct, 1088);
    mlk_hash_j(a->rejection, a->rejection_input, sizeof(a->rejection_input));
}

static void drop_records(void)
{
    scar_public_destroy(record); record = NULL;
    scar_public_destroy(other); other = NULL;
}

static void selftest_case(uint64_t index)
{
    entropy(a->seed, 64); entropy(a->coins, 32);
    require(mlkem_keypair_derand(a->ek, a->dk, a->seed) == 0, "fresh_keygen");
    require(mlkem_enc_derand(a->ct, a->shared, a->ek, a->coins) == 0,
            "fresh_encapsulation");
    record = scar_public_create(a->ek, 1184, 1);
    require(record != NULL, "create_record");
    require((uintptr_t)record % 32 == 0, "record_address_alignment");
    memcpy(a->public_snapshot, record, 3520);
    require(compare_dec(a->dk, a->ct, record, 1, 1) == 0, "valid_cached_dec");
    require(memcmp(a->cached, a->shared, 32) == 0, "encapsulation_shared_equal");
    ScarPublicMatrix *placed = scar_public_init_in_place(placement, 3520,
                                                        a->ek, 1184, 3);
    require(placed != NULL, "in_place_initialization");
    require(compare_dec(a->dk, a->ct, placed, 3, 1) == 0 &&
            memcmp(a->cached, a->shared, 32) == 0, "in_place_same_output");
    scar_public_clear(placed);
    unsigned uncleared = 0;
    for (size_t j = 0; j < 3520; j++) uncleared |= ((const uint8_t *)placement)[j];
    require(uncleared == 0, "in_place_clear_no_free");
    require(compare_dec(a->dk, a->ct, placed, 3, 0) == 0, "cleared_in_place_fallback");
    require(compare_dec(a->dk, a->ct, NULL, 1, 0) == 0, "null_fallback");
    require(compare_dec(a->dk, a->ct, record, 2, 0) == 0, "generation_fallback");
    require(compare_dec(a->dk, a->ct, record, 0, 0) == 0, "zero_generation_fallback");

    memcpy(a->changed_ct, a->ct, 1088);
    a->changed_ct[index % 1088] ^= (uint8_t)(1u << (index % 8));
    require(compare_dec(a->dk, a->changed_ct, record, 1, 1) == 0,
            "modified_ciphertext_dec");
    set_rejection(a->dk, a->changed_ct);
    require(memcmp(a->cached, a->rejection, 32) == 0, "implicit_rejection_J_z_ct");

    memcpy(a->alternate_dk, a->dk, 2400);
    a->alternate_dk[2368 + index % 32] ^= 1;
    require(compare_dec(a->alternate_dk, a->ct, record, 1, 1) == 0,
            "changed_z_valid_dec");
    require(memcmp(a->cached, a->shared, 32) == 0, "valid_output_independent_of_z");
    require(compare_dec(a->alternate_dk, a->changed_ct, record, 1, 1) == 0,
            "changed_z_rejection_dec");
    set_rejection(a->alternate_dk, a->changed_ct);
    require(memcmp(a->cached, a->rejection, 32) == 0, "changed_z_rejection_equal");

    memcpy(a->alternate_dk, a->dk, 2400);
    a->alternate_dk[2336 + index % 32] ^= 1;
    require(compare_dec(a->alternate_dk, a->ct, record, 1, 0) == MLK_ERR_INVALID_SK,
            "invalid_embedded_hash_rejected");

    /* Same rho, changed encoded public vector: decoding must remain per-call.
     * Rehash only to exercise the ordinary API's accepted-key contract; this
     * deliberately inconsistent dk is not asserted to be a generated keypair. */
    memcpy(a->alternate_dk, a->dk, 2400);
    a->alternate_dk[1152 + index % 1152] ^= 1;
    mlk_hash_h(a->alternate_dk + 2336, a->alternate_dk + 1152, 1184);
    require(compare_dec(a->alternate_dk, a->ct, record, 1, 1) == 0,
            "same_rho_different_public_vector");

    memcpy(a->alternate_dk, a->dk, 2400);
    a->alternate_dk[2304 + index % 32] ^= 1;
    mlk_hash_h(a->alternate_dk + 2336, a->alternate_dk + 1152, 1184);
    require(compare_dec(a->alternate_dk, a->ct, record, 1, 0) == 0,
            "changed_rho_fallback");
    other = scar_public_create(a->alternate_dk + 1152, 1184, 1);
    require(other != NULL, "create_other_rho_record");
    require(compare_dec(a->dk, a->ct, other, 1, 0) == 0, "wrong_record_fallback");
    require(compare_dec(a->alternate_dk, a->ct, other, 1, 1) == 0,
            "matching_other_rho_record");

    memcpy(a->alternate_dk, a->dk, 2400);
    a->alternate_dk[index % 1152] ^= 1;
    require(compare_dec(a->alternate_dk, a->ct, record, 1, 1) == 0,
            "changed_private_vector_differential");
    require(memcmp(a->public_snapshot, record, 3520) == 0,
            "borrowed_record_unmodified");
    scar_public_invalidate(record);
    require(compare_dec(a->dk, a->ct, record, 1, 0) == 0, "invalidated_fallback");
    drop_records();
    explicit_bzero(a, sizeof(*a));
}

static void argument_tests(void)
{
    require(scar_public_create(NULL, 1184, 1) == NULL, "null_ek_rejected");
    require(scar_public_create(a->ek, 1183, 1) == NULL, "short_ek_rejected");
    require(scar_public_create(a->ek, 1185, 1) == NULL, "long_ek_rejected");
    require(scar_public_create(a->ek, 1184, 0) == NULL, "zero_generation_rejected");
    memset(placement, 0xa5, 3520);
    require(scar_public_init_in_place(NULL, 3520, a->ek, 1184, 1) == NULL,
            "null_storage_rejected");
    require(scar_public_init_in_place(placement, scar_public_record_bytes() - 1, a->ek, 1184, 1) == NULL,
            "short_storage_rejected");
    require(scar_public_init_in_place((uint8_t *)placement + 1, 3520, a->ek, 1184, 1) == NULL,
            "misaligned_storage_rejected");
    unsigned changed = 0;
    for (size_t j = 0; j < 3520; j++) changed |= ((const uint8_t *)placement)[j] ^ 0xa5;
    require(changed == 0, "rejected_in_place_arguments_preserve_storage");
    memset(a->cached, 0xa5, 32); memset(a->ordinary, 0xa5, 32);
    int used = -1;
    require(scar_public_dec(a->cached, 31, a->ct, 1088, a->dk, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "wrong_output_length");
    require(scar_public_dec(a->cached, 32, a->ct, 1087, a->dk, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "short_ciphertext");
    require(scar_public_dec(a->cached, 32, a->ct, 1089, a->dk, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "long_ciphertext");
    require(scar_public_dec(a->cached, 32, a->ct, 1088, a->dk, 2399,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "short_key");
    require(scar_public_dec(a->cached, 32, a->ct, 1088, a->dk, 2401,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "long_key");
    require(scar_public_dec(a->cached, 32, NULL, 1088, a->dk, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "null_ciphertext");
    require(scar_public_dec(a->cached, 32, a->ct, 1088, NULL, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "null_key");
    require(scar_public_dec(NULL, 32, a->ct, 1088, a->dk, 2400,
                            NULL, 1, &used) == SCAR_PUBLIC_ARGUMENT_ERROR,
            "null_output");
    require(used == 0 && memcmp(a->cached, a->ordinary, 32) == 0,
            "argument_error_does_not_touch_output");
}

static int separator(char ch) { return ch == ' ' || ch == '\t' || ch == '\r'; }
static int nibble(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}
static int read_line(size_t *length)
{
    size_t n = 0; int ch;
    while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
        require(ch != 0 && n + 1 < sizeof(a->line), "kat_line_encoding_or_length");
        a->line[n++] = (char)ch;
    }
    require(!ferror(stdin), "kat_read");
    a->line[n] = '\0'; *length = n;
    return ch != EOF || n != 0;
}
static const char *field(const char *cursor, const char *end, uint8_t *out, size_t bytes)
{
    while (cursor < end && separator(*cursor)) cursor++;
    require((size_t)(end - cursor) >= bytes * 2, "kat_short_field");
    for (size_t i = 0; i < bytes; i++) {
        int hi = nibble(cursor[i * 2]), lo = nibble(cursor[i * 2 + 1]);
        require(hi >= 0 && lo >= 0, "kat_nonhex");
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    cursor += bytes * 2;
    require(cursor == end || separator(*cursor), "kat_long_field");
    return cursor;
}
static void finish_line(const char *cursor, const char *end)
{
    while (cursor < end && separator(*cursor)) cursor++;
    require(cursor == end, "kat_extra_field");
}
static const char *boolean_field(const char *cursor, const char *end, int *value)
{
    while (cursor < end && separator(*cursor)) cursor++;
    require(cursor < end && (*cursor == '0' || *cursor == '1'), "kat_boolean");
    *value = *cursor++ - '0';
    require(cursor == end || separator(*cursor), "kat_long_boolean");
    return cursor;
}

/* Text transport: K seed ek dk; E ek coins ct shared dk;
 * D dk ct shared; S dk expected_check; P ek expected_check.
 * This helper does not authenticate fixture provenance; the notebook must bind
 * prompt/expected/internalProjection IDs and source SHA-256 before transport.
 */
static void kat(void)
{
    uint64_t counts[5] = {0, 0, 0, 0, 0}, total = 0; size_t length;
    while (read_line(&length)) {
        require(total < 100000, "kat_count_limit");
        const char *end = a->line + length, *cursor = a->line;
        require(length >= 3 && separator(cursor[1]), "kat_kind_prefix");
        char kind = *cursor; cursor++;
        if (kind == 'K') {
            cursor = field(cursor, end, a->seed, 64);
            cursor = field(cursor, end, a->ek, 1184);
            cursor = field(cursor, end, a->expected_dk, 2400); finish_line(cursor, end);
            require(mlkem_keypair_derand(a->alternate_ek, a->dk, a->seed) == 0,
                    "kat_keygen");
            require(memcmp(a->ek, a->alternate_ek, 1184) == 0 &&
                    memcmp(a->dk, a->expected_dk, 2400) == 0, "kat_keygen_expected");
            record = scar_public_create(a->ek, 1184, 1);
            require(record != NULL, "kat_keygen_record");
            memset(a->ct, 0, 1088);
            require(compare_dec(a->dk, a->ct, record, 1, 1) == 0,
                    "kat_keygen_cached_differential"); counts[0]++;
        } else if (kind == 'E') {
            cursor = field(cursor, end, a->ek, 1184);
            cursor = field(cursor, end, a->coins, 32);
            cursor = field(cursor, end, a->expected_ct, 1088);
            cursor = field(cursor, end, a->expected_shared, 32);
            cursor = field(cursor, end, a->dk, 2400); finish_line(cursor, end);
            require(memcmp(a->ek, a->dk + 1152, 1184) == 0, "kat_encap_dk_ek_binding");
            require(mlkem_enc_derand(a->ct, a->shared, a->ek, a->coins) == 0,
                    "kat_encapsulation");
            require(memcmp(a->ct, a->expected_ct, 1088) == 0 &&
                    memcmp(a->shared, a->expected_shared, 32) == 0,
                    "kat_encapsulation_expected");
            record = scar_public_create(a->ek, 1184, 1);
            require(record != NULL, "kat_encapsulation_record");
            require(compare_dec(a->dk, a->ct, record, 1, 1) == 0 &&
                    memcmp(a->cached, a->expected_shared, 32) == 0,
                    "kat_encapsulation_cached_expected"); counts[1]++;
        } else if (kind == 'D') {
            cursor = field(cursor, end, a->dk, 2400);
            cursor = field(cursor, end, a->ct, 1088);
            cursor = field(cursor, end, a->expected_shared, 32); finish_line(cursor, end);
            record = scar_public_create(a->dk + 1152, 1184, 1);
            require(record != NULL, "kat_decapsulation_record");
            require(compare_dec(a->dk, a->ct, record, 1, 1) == 0 &&
                    memcmp(a->cached, a->expected_shared, 32) == 0,
                    "kat_decapsulation_expected"); counts[2]++;
        } else if (kind == 'S') {
            int expected;
            cursor = field(cursor, end, a->dk, 2400);
            cursor = boolean_field(cursor, end, &expected); finish_line(cursor, end);
            int valid = mlkem_check_sk(a->dk) == 0;
            require(valid == expected, "kat_private_key_check_expected");
            record = scar_public_create(a->dk + 1152, 1184, 1);
            require(record != NULL, "kat_private_key_check_record");
            memset(a->ct, 0, 1088);
            require((compare_dec(a->dk, a->ct, record, 1, valid) == 0) == expected,
                    "kat_private_key_check_decapsulation"); counts[3]++;
        } else if (kind == 'P') {
            int expected;
            cursor = field(cursor, end, a->ek, 1184);
            cursor = boolean_field(cursor, end, &expected); finish_line(cursor, end);
            require((mlkem_check_pk(a->ek) == 0) == expected,
                    "kat_public_key_check_expected"); counts[4]++;
        } else require(0, "kat_unknown_kind");
        total++; drop_records(); explicit_bzero(a, sizeof(*a));
    }
    require(total > 0, "kat_empty_input");
    printf("kat_passed=1 cases=%" PRIu64 " keygen=%" PRIu64
           " encapsulation=%" PRIu64 " decapsulation=%" PRIu64
           " private_key_check=%" PRIu64 " public_key_check=%" PRIu64 "\n",
           total, counts[0], counts[1], counts[2], counts[3], counts[4]);
}

int main(int argc, char **argv)
{
    if (argc != 2 || (strcmp(argv[1], "selftest") != 0 && strcmp(argv[1], "kat") != 0)) {
        fprintf(stderr, "usage: public_matrix_conformance selftest|kat\n"); return 2;
    }
    setup();
    if (strcmp(argv[1], "selftest") == 0) {
        argument_tests();
        for (uint64_t i = 0; i < 128; i++) selftest_case(i);
        printf("selftest_passed=1 cases=128 valid_decapsulation=1 implicit_rejection=1 "
               "changed_z=1 invalid_key=1 binding_fallback=1 borrowed_immutable=1 "
               "argument_validation=1 in_place=1 record_bytes=%zu payload_bytes=%zu alignment=%zu\n",
               scar_public_record_bytes(), scar_public_payload_bytes(), scar_public_alignment());
    } else kat();
    fprintf(stderr, "functional_checks=%" PRIu64 " secret_arena_bytes=%zu\n", checks, sizeof(*a));
    return 0;
}
