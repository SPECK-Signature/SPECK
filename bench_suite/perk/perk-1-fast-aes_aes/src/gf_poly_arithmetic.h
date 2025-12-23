
#ifndef SIG_PERK_GF_POLY_ARITHMETIC_H
#define SIG_PERK_GF_POLY_ARITHMETIC_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "gf_arithmetic.h"

#if PERK_SECURITY_BYTES == 16
#define GF2_Q_POLY_MODULUS   {0, 3, 12};  // X^12 + X^3 + 1
#define KARAT_MUL_STACK_SIZE 44
#elif PERK_SECURITY_BYTES == 24
#define GF2_Q_POLY_MODULUS   {0, 7, 18};  // X^18 + X^7 + 1
#define KARAT_MUL_STACK_SIZE 76
#elif PERK_SECURITY_BYTES == 32
#define GF2_Q_POLY_MODULUS   {0, 1, 11, 17, 24};  // X^24 + X^17 + X^11+ X + 1
#define KARAT_MUL_STACK_SIZE 92
#else
#error "Invalid PERK_SECURITY_BYTES defined"
#endif

typedef gf2_q_elt gf2_q_poly[PERK_TOWER_FIELD_EXT];
typedef gf2_q_elt gf2_q_poly_ur[2 * PERK_TOWER_FIELD_EXT];

/**
 * @brief folds size coefficients in half_size
 *        half_size must be >= size / 2
 *
 * @param[out] res       result poly
 * @param[in]  src       source poly
 * @param[in]  half_size coefficients in the folded poly
 * @param[in]  remaining coefficients to be folded
 */
static inline void gf2_q_poly_kar_fold(uint32_t res[], const uint32_t src[], int32_t half_size, int32_t remaining) {
    int32_t i = 0;
    for (i = 0; i < remaining; ++i) {
        res[i] = src[i] ^ src[i + half_size];
    }

    for (; i < half_size; i++) {
        res[i] = src[i];
    }
}

static inline void gf2_q_poly_kar_mul_2_by_2(uint32_t o[], const uint32_t a_[], const uint32_t b_[]) {
    __m128i a = _mm_set_epi32(0, 0, a_[1], a_[0]);
    __m128i b = _mm_set_epi32(0, 0, b_[1], b_[0]);

    __m256i a1b1_a0b1a1b0_a0b0 = _mm256_zextsi128_si256(_mm_clmulepi64_si128(a, b, 0));

    // lazy reduce
    // a1b1_a0b1a1b0_a0b0 = sig_perk_gf2_q_avx2_reduce_8x(a1b1_a0b1a1b0_a0b0);

    o[0] = _mm256_extract_epi32(a1b1_a0b1a1b0_a0b0, 0);
    o[1] = _mm256_extract_epi32(a1b1_a0b1a1b0_a0b0, 1);
    o[2] = _mm256_extract_epi32(a1b1_a0b1a1b0_a0b0, 2);
}

static inline void gf2_q_poly_kar_mul_4_by_4(uint32_t o[], const uint32_t a_[], const uint32_t b_[]) {
    __m128i a = ((__m128i *)a_)[0];
    __m128i b = ((__m128i *)b_)[0];

    // fold
    __m128i a2 = _mm_shuffle_epi32(a, 0x4E);
    a2 = _mm_xor_si128(a2, a);
    __m128i b2 = _mm_shuffle_epi32(b, 0x4E);
    b2 = _mm_xor_si128(b2, b);

    __m256i d = _mm256_zextsi128_si256(_mm_clmulepi64_si128(a2, b2, 0));
    __m256i c0 = _mm256_zextsi128_si256(_mm_clmulepi64_si128(a, b, 0));
    __m256i c2 = _mm256_zextsi128_si256(_mm_clmulepi64_si128(a, b, 0x11));

    // c1 = d + c2 + c0
    d = _mm256_xor_si256(d, c2);
    __m256i c1 = _mm256_xor_si256(d, c0);

    // prod = c0 + c1*x^2 + c2*x^4
    // x^0 x^1 x^2 x^3 X^4 x^5 x^6
    // c00 c01 c02
    //         c10 c11 c12
    //                 c20 c21 c22
    c0 = _mm256_xor_si256(c0, _mm256_permute4x64_epi64(c1, 0x93));
    c0 = _mm256_xor_si256(c0, _mm256_permute4x64_epi64(c2, 0x4E));

    // lazy reduce
    // c0 = sig_perk_gf2_q_avx2_reduce_8x(c0);

    ((__m256i *)o)[0] = c0;
}

// defines the template of the unrolled functions
#define gf2_q_poly_kar_mul_N_by_N(size, ha_size, remaining)                                                          \
    static inline void gf2_q_poly_kar_mul_##size##_by_##size(uint32_t o[], const uint32_t a[], const uint32_t b[]) { \
        uint32_t a2[ha_size] __attribute__((aligned(32))) = {0};                                                     \
        uint32_t b2[ha_size] __attribute__((aligned(32))) = {0};                                                     \
                                                                                                                     \
        /* Compute a2 = a0 + a1 and b2 = b0 + b1 */                                                                  \
                                                                                                                     \
        gf2_q_poly_kar_fold(a2, a, ha_size, remaining);                                                              \
        gf2_q_poly_kar_fold(b2, b, ha_size, remaining);                                                              \
                                                                                                                     \
        /* Computation of d = a2*b2 */                                                                               \
                                                                                                                     \
        uint32_t d[2 * ha_size] __attribute__((aligned(32))) = {0};                                                  \
        gf2_q_poly_kar_mul_##ha_size##_by_##ha_size(d, a2, b2);                                                      \
                                                                                                                     \
        /* Computation of c0 = a0*b0 in the low part of o */                                                         \
        gf2_q_poly_kar_mul_##ha_size##_by_##ha_size(o, a, b);                                                        \
                                                                                                                     \
        /* o[ha_size - 1] is zero if gf2_q_poly_mulmod() is called with cleared output buffer */                     \
        /* Computation of c2 = a1*b1 in the high part of o (we ensure o has enough space) */                         \
        gf2_q_poly_kar_mul_##remaining##_by_##remaining(o + 2 * ha_size, a + ha_size, b + ha_size);                  \
                                                                                                                     \
        /* Computation of c1 = d + c2 + c0 */                                                                        \
        for (int32_t i = 0; i < 2 * (remaining - 1) + 1; ++i) {                                                      \
            d[i] = d[i] ^ (o + 2 * ha_size)[i];                                                                      \
        }                                                                                                            \
                                                                                                                     \
        for (int32_t i = 0; i < 2 * (ha_size - 1) + 1; ++i) {                                                        \
            d[i] = d[i] ^ o[i];                                                                                      \
        }                                                                                                            \
                                                                                                                     \
        /* Add c1 to o */                                                                                            \
        for (int32_t i = 0; i <= 2 * (ha_size - 1) + 1; i++) {                                                       \
            o[i + ha_size] = o[i + ha_size] ^ d[i];                                                                  \
        }                                                                                                            \
    }

// defines the unrolled functions
// clang-format off
gf2_q_poly_kar_mul_N_by_N(6, 4, 2)
gf2_q_poly_kar_mul_N_by_N(8, 4, 4)
gf2_q_poly_kar_mul_N_by_N(12, 8, 4)
gf2_q_poly_kar_mul_N_by_N(16, 8, 8)
gf2_q_poly_kar_mul_N_by_N(18, 12, 6)
gf2_q_poly_kar_mul_N_by_N(24, 16, 8)
typedef int realign_formatter; // clang-format doesn't like the above definitions without semicolon
// clang-format on

static inline void gf2_q_poly_mulmod(gf2_q_poly o, const gf2_q_poly a, const gf2_q_poly b) {
    // Step 1 - Carry-less multiplication
    // 1 more element for the use tmp_ur as temporary buffer
    uint32_t tmp_ur[2 * PERK_TOWER_FIELD_EXT /*- 1*/] __attribute__((aligned(32))) = {0};
    uint32_t a32[PERK_TOWER_FIELD_EXT] __attribute__((aligned(32))) = {0};
    uint32_t b32[PERK_TOWER_FIELD_EXT] __attribute__((aligned(32))) = {0};
    for (int i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        a32[i] = a[i];
        b32[i] = b[i];
    }
#if (PERK_SECURITY_BYTES == 16)
    gf2_q_poly_kar_mul_12_by_12(tmp_ur, a32, b32);
#elif (PERK_SECURITY_BYTES == 24)
    gf2_q_poly_kar_mul_18_by_18(tmp_ur, a32, b32);
#elif (PERK_SECURITY_BYTES == 32)
    gf2_q_poly_kar_mul_24_by_24(tmp_ur, a32, b32);
#endif

    // Step 2 - Modular reduction modulo GF2_Q_POLY_MODULUS
    const uint32_t modulus[] = GF2_Q_POLY_MODULUS;
    const size_t modulus_nb_coefs = sizeof(modulus) / sizeof(modulus[0]);
    int16_t max_deg = 2 * PERK_TOWER_FIELD_EXT - 1;
    for (int16_t i = max_deg - PERK_TOWER_FIELD_EXT; i > 0; --i) {
        for (size_t j = 0; j < modulus_nb_coefs - 1; ++j) {
            tmp_ur[i + modulus[j] - 1] = tmp_ur[i + modulus[j] - 1] ^ tmp_ur[i + (PERK_TOWER_FIELD_EXT - 1)];
        }
        tmp_ur[i + (PERK_TOWER_FIELD_EXT - 1)] = 0;
    }

    // Step 3 - lazy GF2^Q reduction
    ((__m256i *)tmp_ur)[0] = sig_perk_gf2_q_avx2_reduce_8x(((__m256i *)tmp_ur)[0]);
    ((__m256i *)tmp_ur)[1] = sig_perk_gf2_q_avx2_reduce_8x(((__m256i *)tmp_ur)[1]);
#if (PERK_SECURITY_BYTES == 32) || (PERK_SECURITY_BYTES == 24)
    ((__m256i *)tmp_ur)[2] = sig_perk_gf2_q_avx2_reduce_8x(((__m256i *)tmp_ur)[2]);
#endif

    for (int i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        o[i] = tmp_ur[i];
    }
}

static inline void gf2_q_poly_scal_mul(gf2_q_poly c, const gf2_q_poly a, const gf2_q_elt b) {
    __m128i const c32 = _mm_set1_epi32(b);

    // 4 by 4
    for (unsigned j = 0; j < (PERK_TOWER_FIELD_EXT - 3); j += 4) {
        __m128i av = _mm_set_epi32(a[3 + j], a[2 + j], a[1 + j], a[0 + j]);

        __m128i d0 = _mm_clmulepi64_si128(av, c32, 0x00);
        __m128i d1 = _mm_clmulepi64_si128(av, c32, 0x11);
        __m256i d = _mm256_set_m128i(d1, d0);

        uint32_t dest[8] __attribute__((aligned(32))) = {0};
        ((__m256i *)dest)[0] = sig_perk_gf2_q_avx2_reduce_8x(d);

        for (int i = 0; i < 4; i++) {
            c[i + j] = dest[i * 2];
        }
    }
// last 2 for level3
#if (PERK_SECURITY_BYTES == 24)
    __m128i av = _mm_set_epi32(a[3 + 14], a[2 + 14], a[1 + 14], a[0 + 14]);

    // __m128i d0 = _mm_clmulepi64_si128(av, c32, 0x00);
    __m128i d1 = _mm_clmulepi64_si128(av, c32, 0x11);
    // __m256i d = _mm256_set_m128i(d1, d0);

    uint32_t dest[8] __attribute__((aligned(32))) = {0};
    ((__m256i *)dest)[0] = sig_perk_gf2_q_avx2_reduce_8x(_mm256_castsi128_si256(d1));

    for (int i = 0; i < 2; i++) {
        c[i + 16] = dest[i * 2];
    }

#endif
}

static inline void gf2_q_poly_scal_mul_ref(gf2_q_poly c, const gf2_q_poly a, const gf2_q_elt b) {
    for (size_t i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        sig_perk_gf2_q_mul(&c[i], a[i], b);
    }
}

static inline void gf2_q_poly_add(gf2_q_poly c, const gf2_q_poly a, const gf2_q_poly b) {
    for (uint8_t i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        c[i] = a[i] ^ b[i];
    }
}

static inline void gf2_q_poly_copy(gf2_q_poly b, const gf2_q_poly a) {
    for (uint8_t i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        b[i] = a[i];
    }
}

static inline uint8_t gf2_q_poly_is_zero(const gf2_q_poly a) {
    for (uint8_t i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        if (a[i] != 0) {
            return 1;
        }
    }
    return 0;
}

static inline void gf2_q_poly_expo(gf2_q_poly b, const gf2_q_poly a, uint8_t d) {
    if (d == 0) {
        b[0] = 1;
        for (unsigned i = 1; i < PERK_TOWER_FIELD_EXT; ++i) {
            b[i] = 0;
        }
    } else {
        gf2_q_poly tmp = {0};
        gf2_q_poly_copy(tmp, a);
        gf2_q_poly_copy(b, a);
        for (uint8_t i = 1; i < d; ++i) {
            gf2_q_poly_mulmod(b, b, tmp);
        }
    }
}

static inline void sig_perk_print_tower_field_element(gf2_q_poly a) {
    for (int i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        printf("%03" PRIx16 " ", a[i]);
    }
}

static inline uint8_t gf2_q_poly_cmp(const gf2_q_poly b, const gf2_q_poly a) {
    for (uint8_t i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        if (a[i] != b[i]) {
            return 1;
        }
    }
    return 0;
}

#endif  // SIG_PERK_GF_POLY_ARITHMETIC_H
