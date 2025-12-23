
#ifndef SIG_PERK_GF2_ARITHMETIC_AVX2_H
#define SIG_PERK_GF2_ARITHMETIC_AVX2_H

#include <emmintrin.h>
#include <immintrin.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

// GF2_128
// Irreducible polynomial X^128 + X^7 + X^2 + X^1 + 1

#define GF2_LAMBDA_FIELD_M 128

#define GF2_LAMBDA_ELT_SIZE          2
#define GF2_LAMBDA_ELT_UR_SIZE       4
#define GF2_LAMBDA_ELT_UINT8_SIZE    16
#define GF2_LAMBDA_ELT_UR_UINT8_SIZE 32

typedef int64_t gf2_lambda_elt_int;
typedef uint64_t gf2_lambda_elt_uint;
typedef uint64_t gf2_lambda_elt[GF2_LAMBDA_ELT_SIZE] __attribute__((aligned(16)));
typedef uint64_t gf2_lambda_elt_ur[GF2_LAMBDA_ELT_UR_SIZE] __attribute__((aligned(16)));
typedef uint64_t *gf2_lambda_elt_ptr;

static inline void sig_perk_gf2_lambda_ur_set(gf2_lambda_elt_ur o, const gf2_lambda_elt_ur e) {
    for (size_t i = 0; i < GF2_LAMBDA_ELT_UR_SIZE; i++) {
        o[i] = e[i];
    }
}

static inline void sig_perk_gf2_lambda_add(gf2_lambda_elt o, const gf2_lambda_elt e1, const gf2_lambda_elt e2) {
    o[0] = e1[0] ^ e2[0];
    o[1] = e1[1] ^ e2[1];
}

static inline void sig_perk_gf2_lambda_reduce(gf2_lambda_elt o, gf2_lambda_elt_ur e) {
    e[2] ^= (e[3] >> 57) ^ (e[3] >> 62) ^ (e[3] >> 63);

    e[1] ^= (e[3] << 7) ^ (e[3] << 2) ^ (e[3] << 1) ^ e[3];

    uint64_t tmp = e[2];
    e[0] ^= (tmp << 7) ^ (tmp << 2) ^ (tmp << 1) ^ tmp;
    e[1] ^= (tmp >> 57) ^ (tmp >> 62) ^ (tmp >> 63);

    o[0] = e[0];
    o[1] = e[1];
}

static inline void sig_perk_gf2_lambda_ur_mul(gf2_lambda_elt_ur o, gf2_lambda_elt e1, gf2_lambda_elt e2) {
    __m128i a = _mm_load_si128((__m128i *)e1);
    __m128i b = _mm_load_si128((__m128i *)e2);

    __m128i a0_b0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i a0_b1 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i a1_b0 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i a1_b1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i c1 = _mm_xor_si128(a0_b1, a1_b0);

    o[0] = _mm_extract_epi64(a0_b0, 0);
    o[1] = _mm_extract_epi64(a0_b0, 1) ^ _mm_extract_epi64(c1, 0);
    o[2] = _mm_extract_epi64(a1_b1, 0) ^ _mm_extract_epi64(c1, 1);
    o[3] = _mm_extract_epi64(a1_b1, 1);
}

static inline void sig_perk_gf2_lambda_mul_orig(gf2_lambda_elt o, gf2_lambda_elt e1, gf2_lambda_elt e2) {
    gf2_lambda_elt_ur tmp;
    sig_perk_gf2_lambda_ur_mul(tmp, e1, e2);
    sig_perk_gf2_lambda_reduce(o, tmp);
}

static inline void sig_perk_gf2_lambda_mul(gf2_lambda_elt o, const gf2_lambda_elt e1, const gf2_lambda_elt e2) {
    __m128i a = _mm_load_si128((__m128i *)e1);
    __m128i b = _mm_load_si128((__m128i *)e2);

    __m128i a1_b1 = _mm_clmulepi64_si128(a, b, 0x11);
    __m128i a1_b0 = _mm_clmulepi64_si128(a, b, 0x01);
    __m128i a0_b1 = _mm_clmulepi64_si128(a, b, 0x10);
    __m128i a0_b0 = _mm_clmulepi64_si128(a, b, 0x00);
    __m128i c1 = _mm_xor_si128(a0_b1, a1_b0);

    __m128i t1 = _mm_clmulepi64_si128(a1_b1, _mm_set_epi64x(0, 0x87), 0x01);

    t1 = _mm_xor_si128(t1, c1);  // xor c1 with t1 to save some xor and shifts

    __m128i hi = _mm_xor_si128(a1_b1, _mm_srli_si128(t1, 8));
    __m128i lo = _mm_xor_si128(a0_b0, _mm_slli_si128(t1, 8));

    __m128i t2 = _mm_clmulepi64_si128(hi, _mm_set_epi64x(0, 0x87), 0x00);

    *((__m128i *)o) = _mm_xor_si128(lo, t2);
}

#endif  // SIG_PERK_GF2_ARITHMETIC_H
