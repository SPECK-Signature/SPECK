#ifndef SIG_PERK_GF_Q_ARITHMETIC_H
#define SIG_PERK_GF_Q_ARITHMETIC_H

#include <emmintrin.h>
#include <immintrin.h>
#include <inttypes.h>
#include <smmintrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wmmintrin.h>
#include "parameters.h"

#include "gf_lambda_arithmetic.h"

typedef uint32_t gf_elt_ur;
typedef uint16_t gf_elt;

static inline void sig_perk_gf_ur_mul(gf_elt_ur *o, gf_elt e1, gf_elt e2) {
    __m128i va = _mm_cvtsi32_si128(e1);
    __m128i vb = _mm_cvtsi32_si128(e2);
    __m128i vab = _mm_clmulepi64_si128(va, vb, 0x00);
    *o = _mm_cvtsi128_si32(vab);
}

static inline uint32_t sig_perk_gf_reduce(uint64_t field_value, uint16_t GF_FIELD_POLY, uint16_t GF_FIELD_M) {
#define CEIL_DIV(a, b) ((a) / (b) + ((a) % (b) == 0 ? 0 : 1))
    // Compute the distance between the primitive polynomial first two set bits
    size_t lz1 = __builtin_clz(GF_FIELD_POLY);
    size_t lz2 = __builtin_clz(GF_FIELD_POLY ^ (1 << GF_FIELD_M));
    size_t dist = lz2 - lz1;

    // Deduce the number of steps of reduction
    size_t reduction_steps = CEIL_DIV((GF_FIELD_M * 2 - 2) - (GF_FIELD_M - 1), dist);

    printf("\n steps = %zu\n", reduction_steps);
    printf("\n 2nd loop = %d\n", __builtin_popcount(GF_FIELD_POLY) - 2);

    for (size_t step = 0; step < reduction_steps; ++step) {
        uint64_t reduction_value = field_value >> GF_FIELD_M;
        field_value &= (1 << GF_FIELD_M) - 1;
        field_value ^= reduction_value;

        size_t prev_zero_bit_pos = 0;
        uint16_t remainder_poly = GF_FIELD_POLY ^ 1;

        for (size_t bit_count = __builtin_popcount(GF_FIELD_POLY) - 2; bit_count; --bit_count) {
            size_t curr_zero_bit_pos = __builtin_ctz(remainder_poly);
            size_t shift = curr_zero_bit_pos - prev_zero_bit_pos;
            reduction_value <<= shift;
            field_value ^= reduction_value;
            remainder_poly ^= 1 << curr_zero_bit_pos;
            prev_zero_bit_pos = curr_zero_bit_pos;
        }
    }

    return field_value;
}

typedef uint16_t gf2_q_elt;
#define GF2_Q_ELT_UINT8_SIZE 2

// GF2_lambda
uint8_t sig_perk_gf2_lambda_elt_get_coefficient(const gf2_lambda_elt e, uint32_t index);
void sig_perk_gf2_lambda_elt_print(const gf2_lambda_elt e);
void sig_perk_gf2_lambda_elt_ur_print(const gf2_lambda_elt_ur e);
void sig_perk_gf2_lambda_set(gf2_lambda_elt o, const gf2_lambda_elt e);
void sig_perk_gf2_lambda_from_bytes(gf2_lambda_elt e, uint8_t bytes_array[GF2_LAMBDA_ELT_UINT8_SIZE]);
void sig_perk_gf2_lambda_to_bytes(uint8_t bytes_array[GF2_LAMBDA_ELT_UINT8_SIZE], gf2_lambda_elt e);

// GF2_11
#if (PERK_PARAM_Q != 11)
#error implementation is only for GF(2^11)
#endif

#define GF2_Q_FIELD_MUL_ORDER     ((1 << PERK_PARAM_Q) - 1)
#define GF2_Q_FIELD_POLY          0X805
#define GF2_KAPPA_FIELD_MUL_ORDER ((1 << PERK_PARAM_Q) - 1)
#define GF2_KAPPA_FIELD_POLY      0X805

static inline void sig_perk_gf2_q_add(gf2_q_elt *c, gf2_q_elt a, gf2_q_elt b) {
    *c = a ^ b;
}

static inline gf2_q_elt sig_perk_gf2_q_reduce(uint64_t x) {
    for (size_t i = 0; i < 2; ++i) {
        uint64_t mod = x >> PERK_PARAM_Q;
        x &= (1 << PERK_PARAM_Q) - 1;
        x ^= mod;
        mod <<= 2;
        x ^= mod;
    }
    return (gf2_q_elt)x;
}

static inline void sig_perk_gf2_q_mul(gf2_q_elt *c, gf2_q_elt a, gf2_q_elt b) {
    __m128i va = _mm_cvtsi32_si128(a);
    __m128i vb = _mm_cvtsi32_si128(b);
    __m128i vab = _mm_clmulepi64_si128(va, vb, 0);
    uint32_t ab = _mm_cvtsi128_si32(vab);

    *c = sig_perk_gf2_q_reduce(ab);
}

/**
 * Squares an element of GF(2^GF_M).
 * @returns a^2
 * @param[in] a Element of GF(2^GF_M)
 */
static inline gf2_q_elt sig_perk_gf2_q_square(gf2_q_elt a) {
    uint32_t b = a;
    uint32_t s = b & 1;
    for (size_t i = 1; i < PERK_PARAM_Q; ++i) {
        b <<= 1;
        s ^= b & (1 << 2 * i);
    }

    return sig_perk_gf2_q_reduce(s);
}

/**
 * Compute the inverse of an element of GF(2^GF_M).
 * @returns a^(-1)
 * @param[in] a Element of GF(2^GF_M)
 */
static inline void sig_perk_gf2_q_inverse(gf2_q_elt *b, gf2_q_elt a) {
    size_t pow = (1 << PERK_PARAM_Q) - 2;
    *b = 1;

    do {
        if (pow & 1)
            sig_perk_gf2_q_mul(b, *b, a);
        a = sig_perk_gf2_q_square(a);
        pow >>= 1;
    } while (pow);
}

// GF2_64
// GF(2^64) with X^64 + X^4 + X^3 + X^1 + 1

#define GF2_64_FIELD_M       64
#define GF2_64_ELT_SIZE      1
#define GF2_64_ELT_DATA_SIZE 1

#define GF2_64_ELT_UR_SIZE      2
#define GF2_64_ELT_UR_DATA_SIZE 2

#define GF2_64_ELT_UINT8_SIZE    8
#define GF2_64_ELT_UR_UINT8_SIZE 16

typedef int64_t gf2_64_elt_int;
typedef uint64_t gf2_64_elt_uint;
typedef uint64_t gf2_64_elt[GF2_64_ELT_SIZE];
typedef uint64_t gf2_64_elt_ur[GF2_64_ELT_UR_SIZE];
typedef uint64_t *gf2_64_elt_ptr;

void sig_perk_gf2_lambda_from_gf2_64(gf2_lambda_elt o, const gf2_64_elt e);
void sig_perk_gf2_64_from_bytes(gf2_64_elt e, uint8_t bytes_array[GF2_64_ELT_UINT8_SIZE]);

static inline void sig_perk_gf2_64_add(gf2_64_elt o, const gf2_64_elt e1, const gf2_64_elt e2) {
    o[0] = e1[0] ^ e2[0];
}

static inline void sig_perk_gf2_64_ur_mul(gf2_64_elt_ur o, gf2_64_elt e1, gf2_64_elt e2) {
    __m128i a = _mm_loadl_epi64((__m128i *)e1);
    __m128i b = _mm_loadl_epi64((__m128i *)e2);

    __m128i a0_b0 = _mm_clmulepi64_si128(a, b, 0x00);

    _mm_store_si128((__m128i *)o, a0_b0);
}

static inline void sig_perk_gf2_64_reduce(gf2_64_elt o, const gf2_64_elt_ur e) {
    uint64_t tmp = e[1] ^ (e[1] >> 61) ^ (e[1] >> 60);
    o[0] = e[0] ^ tmp ^ (tmp << 1) ^ (tmp << 3) ^ (tmp << 4);
}

static inline void sig_perk_gf2_64_mul(gf2_64_elt o, gf2_64_elt e1, gf2_64_elt e2) {
    gf2_64_elt_ur tmp;
    sig_perk_gf2_64_ur_mul(tmp, e1, e2);
    sig_perk_gf2_64_reduce(o, tmp);
}

static inline void sig_perk_gf2_64_ur_set(gf2_64_elt_ur o, const gf2_64_elt_ur e) {
    for (size_t i = 0; i < GF2_64_ELT_UR_SIZE; i++) {
        o[i] = e[i];
    }
}

static inline uint8_t sig_perk_gf2_64_elt_get_coefficient(const gf2_64_elt e, uint32_t index) {
    uint64_t w = 0;

    for (uint8_t i = 0; i < GF2_64_ELT_DATA_SIZE; i++) {
        w |= -((i ^ (index >> 6)) == 0) & e[i];
    }

    return (w >> (index & 63)) & 1;
}

// GF2_8
// GF(2^8) with X^8 + X^4 + X^3 + X + 1
#define GF2_8_FIELD_POLY 0x11B

#define GF2_8_FIELD_M  8
#define GF2_8_ELT_SIZE 1

#define GF2_8_ELT_UINT8_SIZE    1
#define GF2_8_ELT_UR_UINT8_SIZE 2

typedef uint8_t gf2_8_elt;
typedef uint32_t gf2_8_elt_ur;

static inline uint32_t sig_perk_gf2_8_reduce(uint64_t field_value) {
    for (size_t step = 0; step < 2; ++step) {
        size_t prev_zero_bit_pos = 0;
        uint64_t reduction_value;
        prev_zero_bit_pos = 0;
        uint16_t remainder_poly = GF2_8_FIELD_POLY ^ 1;
        reduction_value = field_value >> GF2_8_FIELD_M;
        field_value &= (1 << GF2_8_FIELD_M) - 1;
        field_value ^= reduction_value;

        for (size_t i = 0; i < 3; ++i) {
            size_t curr_zero_bit_pos = __builtin_ctz(remainder_poly);
            size_t shift = curr_zero_bit_pos - prev_zero_bit_pos;
            reduction_value <<= shift;
            field_value ^= reduction_value;
            remainder_poly ^= 1 << curr_zero_bit_pos;
            prev_zero_bit_pos = curr_zero_bit_pos;
        }
    }
    return field_value;
}

static inline void sig_perk_gf2_8_mul(gf2_8_elt *o, gf2_8_elt e1, gf2_8_elt e2) {
    gf2_8_elt_ur tmp = {0};
    sig_perk_gf_ur_mul(&tmp, e1, e2);
    *o = sig_perk_gf2_8_reduce((uint64_t)tmp);
}

static inline void sig_perk_gf2_8_add(gf2_8_elt *o, const gf2_8_elt e1, const gf2_8_elt e2) {
    *o = e1 ^ e2;
}

// GF2_9
// GF(2^9) with X^9 + X + 1
#define GF2_9_FIELD_POLY 0x203

#define GF2_9_FIELD_M  9
#define GF2_9_ELT_SIZE 1

#define GF2_9_ELT_UINT8_SIZE    2
#define GF2_9_ELT_UR_UINT8_SIZE 2

typedef uint16_t gf2_9_elt;
typedef uint32_t gf2_9_elt_ur;

static inline uint32_t sig_perk_gf2_9_reduce(uint64_t field_value) {
    uint64_t reduction_value = field_value >> GF2_9_FIELD_M;
    field_value &= (1 << GF2_9_FIELD_M) - 1;
    field_value ^= reduction_value;
    reduction_value <<= 1;
    field_value ^= reduction_value;

    return field_value;
}

static inline void sig_perk_gf2_9_mul(gf2_9_elt *o, gf2_9_elt e1, gf2_9_elt e2) {
    gf2_9_elt_ur tmp = {0};
    sig_perk_gf_ur_mul(&tmp, e1, e2);
    *o = sig_perk_gf2_9_reduce((uint64_t)tmp);
}

static inline void sig_perk_gf2_9_add(gf2_9_elt *o, const gf2_9_elt e1, const gf2_9_elt e2) {
    *o = e1 ^ e2;
}

// GF2_12
// GF(2^12) with X^12 + X^3 + 1
#define GF2_12_FIELD_POLY 0x1009

#define GF2_12_FIELD_M  12
#define GF2_12_ELT_SIZE 1

#define GF2_12_ELT_UINT8_SIZE    2
#define GF2_12_ELT_UR_UINT8_SIZE 3

typedef uint16_t gf2_12_elt;
typedef uint32_t gf2_12_elt_ur;

static inline uint32_t sig_perk_gf2_12_reduce(uint64_t field_value) {
    for (size_t step = 0; step < 2; ++step) {
        size_t prev_zero_bit_pos = 0;
        uint64_t reduction_value;
        uint16_t remainder_poly = GF2_12_FIELD_POLY ^ 1;
        reduction_value = field_value >> GF2_12_FIELD_M;
        field_value &= (1 << GF2_12_FIELD_M) - 1;
        field_value ^= reduction_value;

        size_t curr_zero_bit_pos = __builtin_ctz(remainder_poly);
        size_t shift = curr_zero_bit_pos - prev_zero_bit_pos;
        reduction_value <<= shift;
        field_value ^= reduction_value;
    }
    return field_value;
}

static inline void sig_perk_gf2_12_mul(gf2_12_elt *o, gf2_12_elt e1, gf2_12_elt e2) {
    gf2_12_elt_ur tmp = {0};
    sig_perk_gf_ur_mul(&tmp, e1, e2);
    *o = sig_perk_gf2_12_reduce((uint64_t)tmp);
}

static inline void sig_perk_gf2_12_add(gf2_12_elt *o, const gf2_12_elt e1, const gf2_12_elt e2) {
    *o = e1 ^ e2;
}

// GF2_13
// GF(2^13) with X^13 + X^4 + X^3 + X + 1
#define GF2_13_FIELD_POLY 0x201b

#define GF2_13_FIELD_M  13
#define GF2_12_ELT_SIZE 1

#define GF2_13_ELT_UINT8_SIZE    2
#define GF2_13_ELT_UR_UINT8_SIZE 3

typedef uint16_t gf2_13_elt;
typedef uint32_t gf2_13_elt_ur;

static inline uint32_t sig_perk_gf2_13_reduce(uint64_t field_value) {
    for (size_t step = 0; step < 2; ++step) {
        size_t prev_zero_bit_pos = 0;
        uint64_t reduction_value;
        prev_zero_bit_pos = 0;
        uint16_t remainder_poly = GF2_13_FIELD_POLY ^ 1;
        reduction_value = field_value >> GF2_13_FIELD_M;
        field_value &= (1 << GF2_13_FIELD_M) - 1;
        field_value ^= reduction_value;

        for (size_t i = 0; i < 3; ++i) {
            size_t curr_zero_bit_pos = __builtin_ctz(remainder_poly);
            size_t shift = curr_zero_bit_pos - prev_zero_bit_pos;
            reduction_value <<= shift;
            field_value ^= reduction_value;
            remainder_poly ^= 1 << curr_zero_bit_pos;
            prev_zero_bit_pos = curr_zero_bit_pos;
        }
    }
    return field_value;
}

static inline void sig_perk_gf2_13_mul(gf2_13_elt *o, gf2_13_elt e1, gf2_13_elt e2) {
    gf2_13_elt_ur tmp = {0};
    sig_perk_gf_ur_mul(&tmp, e1, e2);
    *o = sig_perk_gf2_13_reduce((uint64_t)tmp);
}

static inline void sig_perk_gf2_13_add(gf2_13_elt *o, const gf2_13_elt e1, const gf2_13_elt e2) {
    *o = e1 ^ e2;
}

#define M256I_32x8_INIT(val)                                                                 \
    {((uint64_t)(val) << 32U) | (uint64_t)(val), ((uint64_t)(val) << 32U) | (uint64_t)(val), \
     ((uint64_t)(val) << 32U) | (uint64_t)(val), ((uint64_t)(val) << 32U) | (uint64_t)(val)}
#define M256I_32x8_INIT8(val7, val6, val5, val4, val3, val2, val1, val0)                         \
    {((uint64_t)(val1) << 32U) | (uint64_t)(val0), ((uint64_t)(val3) << 32U) | (uint64_t)(val2), \
     ((uint64_t)(val5) << 32U) | (uint64_t)(val4), ((uint64_t)(val7) << 32U) | (uint64_t)(val6)}

static const __m256i v8_GF_MUL_ORDER = M256I_32x8_INIT((1 << PERK_PARAM_Q) - 1);

static inline __m256i sig_perk_gf2_q_avx2_reduce_8x(__m256i vx) {
    // reduce
    __m256i vmod;
    vmod = _mm256_srli_epi32(vx, PERK_PARAM_Q);  // mod = x >> PERK_PARAM_Q
    vx = _mm256_and_si256(vx, v8_GF_MUL_ORDER);  // x = x & GF_MUL_ORDER
    vx = _mm256_xor_si256(vx, vmod);             // x = x ^ mod
    vmod = _mm256_slli_epi32(vmod, 2);           // mod = mod << 2
    vx = _mm256_xor_si256(vx, vmod);             // x = x ^ mod

    vmod = _mm256_srli_epi32(vx, PERK_PARAM_Q);  // mod = x >> PERK_PARAM_Q
    vx = _mm256_and_si256(vx, v8_GF_MUL_ORDER);  // x = x & GF_MUL_ORDER
    vx = _mm256_xor_si256(vx, vmod);             // x = x ^ mod
    vmod = _mm256_slli_epi32(vmod, 2);           // mod = mod << 2
    return _mm256_xor_si256(vx, vmod);           // x = x ^ mod
}

static inline __m128i sig_perk_gf2_q_avx2_polymul(__m128i_u ab, __m128i cd) {
    // vx = ac, ad+bc, bd
    __m128i vx = _mm_clmulepi64_si128(ab, cd, 0);

    // reduce
    return _mm256_castsi256_si128(sig_perk_gf2_q_avx2_reduce_8x(_mm256_zextsi128_si256(vx)));
}

#endif  // SIG_PERK_GF_Q_ARITHMETIC_H
