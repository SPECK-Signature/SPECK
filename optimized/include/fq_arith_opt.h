/**
 *
 * Optimized Implementation of LESS.
 *
 * @version 1.2 (May 2023)
 *
 * @author Duc Tri Nguyen <dnguye69@gmu.edu>
 * @author Alessandro Barenghi <alessandro.barenghi@polimi.it>
 * @author Gerardo Pelosi <gerardo.pelosi@polimi.it>
 * @author Floyd Zweydinger <zweydfg8+github@rub.de>
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 **/

#pragma once
#include <stdint.h>

#include "parameters.h"
#include "rng.h"

#define NUM_BITS_Q (BITS_TO_REPRESENT(Q))


#define DEF_RAND_STATE(FUNC_NAME, EL_T, MINV, MAXV) \
static inline void FUNC_NAME(SHAKE_STATE_STRUCT *shake_monomial_state, EL_T *buffer, size_t num_elements) { \
   typedef uint64_t WORD_T; \
   static const EL_T MIN_VALUE = (MINV);\
   static const EL_T MAX_VALUE = (MAXV); \
   static const EL_T SPAN = MAX_VALUE - MIN_VALUE; \
   static const size_t REQ_BITS = BITS_TO_REPRESENT(SPAN); \
   static const EL_T EL_MASK = ((EL_T) 1 << REQ_BITS) - 1; \
   WORD_T word; \
   size_t count = 0; \
   do { \
      csprng_randombytes((unsigned char *) &word, sizeof(WORD_T), shake_monomial_state); \
      for (uint32_t i = 0; i < ((sizeof(WORD_T)*8u) / REQ_BITS); i++) { \
         EL_T rnd_value = word & EL_MASK; \
         if (rnd_value <= SPAN) buffer[count++] = rnd_value + MIN_VALUE; \
         if (count >= num_elements) return; \
         word >>= REQ_BITS; \
      } \
   } while (1); }

#define DEF_RAND(FUNC_NAME, EL_T, MINV, MAXV) \
static inline void FUNC_NAME(EL_T *buffer, size_t num_elements) { \
   typedef uint64_t WORD_T; \
   static const EL_T MIN_VALUE = (MINV); \
   static const EL_T MAX_VALUE = (MAXV); \
   static const EL_T SPAN = MAX_VALUE - MIN_VALUE; \
   static const size_t REQ_BITS = BITS_TO_REPRESENT(SPAN); \
   static const EL_T EL_MASK = ((EL_T) 1 << REQ_BITS) - 1; \
   WORD_T word; \
   size_t count = 0; \
   do { \
      randombytes((unsigned char *) &word, sizeof(WORD_T)); \
      for (uint32_t i = 0; i < ((sizeof(WORD_T)*8) / REQ_BITS); i++) { \
         EL_T rnd_value = word & EL_MASK; \
         if (rnd_value <= SPAN) buffer[count++] = rnd_value + MIN_VALUE; \
         if (count >= num_elements) return; \
         word >>= REQ_BITS; \
      } \
   } while (1); }


/* GCC actually inlines and vectorizes Barrett's reduction already.
 * Backup implementation for less aggressive compilers follows */




static inline
FQ_ELEM fq_cond_sub(const FQ_ELEM x) {
    // equivalent to: (x >= Q) ? (x - Q) : x
    // likely to be ~ constant-time (a "smart" compiler might turn this into conditionals though)
    FQ_ELEM sub_q = x - Q;
    FQ_ELEM mask = -(sub_q >> NUM_BITS_Q);
    return (mask & Q) + sub_q;
}

static inline
FQ_ELEM fq_red(const FQ_DOUBLEPREC x) {
    return fq_cond_sub((x >> NUM_BITS_Q) + ((FQ_ELEM) x & Q));
}

static inline
FQ_ELEM fq_sub(const FQ_ELEM x, const FQ_ELEM y) {
    return fq_cond_sub(x + Q - y);
}

static inline
FQ_ELEM fq_mul(const FQ_ELEM x, const FQ_ELEM y) {
    return fq_red(((FQ_DOUBLEPREC)x) *(FQ_DOUBLEPREC)y);
}

static inline
FQ_ELEM fq_add(const FQ_ELEM x, const FQ_ELEM y) {
      return (x + y) % Q;
}
/*
 * Barrett multiplication for uint8_t Q = 127
 */
static inline 
FQ_ELEM br_mul(FQ_ELEM a, FQ_ELEM b)
{
   FQ_DOUBLEPREC lo, hi;
   lo = a * b;
   hi = lo >> 7;
   lo += hi;
   hi <<= 7;
   return lo - hi;
}

/*
 * Barrett reduction for uint8_t with prime Q = 127
 */
static inline 
FQ_ELEM br_red(FQ_ELEM a)
{
   FQ_ELEM t;
   t = a >> 7;
   t &= Q;
   a += t;
   a &= Q;
   return a;
}

/*
 * Barrett reduction for uint16_t with prime Q = 127
 */
static inline 
FQ_DOUBLEPREC br_red16(FQ_DOUBLEPREC x)
{
   FQ_DOUBLEPREC y;
   FQ_DOUBLEPREC a;

   a = x + 1;
   a = (a << 7) + a;
   y = a >> 14;
   y = (y << 7) - y;
   return x - y;
}


/// NOTE: maybe dont use it for sensitive data
static const uint8_t fq_inv_table[127] __attribute__((aligned(64))) = {
   0, 1, 64, 85, 32, 51, 106, 109, 16, 113, 89, 104, 53, 88, 118, 17, 8, 15, 120, 107, 108, 121, 52, 116, 90, 61, 44, 80, 59, 92, 72, 41, 4, 77, 71, 98, 60, 103, 117, 114, 54, 31, 124, 65, 26, 48, 58, 100, 45, 70, 94, 5, 22, 12, 40, 97, 93, 78, 46, 28, 36, 25, 84, 125, 2, 43, 102, 91, 99, 81, 49, 34, 30, 87, 115, 105, 122, 33, 57, 82, 27, 69, 79, 101, 62, 3, 96, 73, 13, 10, 24, 67, 29, 56, 50, 123, 86, 55, 35, 68, 47, 83, 66, 37, 11, 75, 6, 19, 20, 7, 112, 119, 110, 9, 39, 74, 23, 38, 14, 111, 18, 21, 76, 95, 42, 63, 126
};

static const uint8_t fq_square_table[128] __attribute__((aligned(64))) = {
0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 17, 42, 69, 98, 2, 35, 70, 107, 19, 60, 103, 21, 68, 117, 41, 94, 22, 79, 11, 72, 8, 73, 13, 82, 26, 99, 47, 124, 76, 30, 113, 71, 31, 120, 84, 50, 18, 115, 87, 61, 37, 15, 122, 104, 88, 74, 62, 52, 44, 38, 34, 32, 32, 34, 38, 44, 52, 62, 74, 88, 104, 122, 15, 37, 61, 87, 115, 18, 50, 84, 120, 31, 71, 113, 30, 76, 124, 47, 99, 26, 82, 13, 73, 8, 72, 11, 79, 22, 94, 41, 117, 68, 21, 103, 60, 19, 107, 70, 35, 2, 98, 69, 42, 17, 121, 100, 81, 64, 49, 36, 25, 16, 9, 4, 1
};

static const uint8_t fq_sqrt_table[128] __attribute__((aligned(64))) = {
0, 1, 16, 0, 2, 0, 0, 0, 32, 3, 0, 30, 0, 34, 0, 53, 4, 12, 48, 20, 0, 23, 28, 0, 0, 5, 36, 0, 0, 0, 41, 44, 63, 0, 62, 17, 6, 52, 61, 0, 0, 26, 13, 0, 60, 0, 0, 38, 0, 7, 47, 0, 59, 0, 0, 0, 0, 0, 0, 0, 21, 51, 58, 0, 8, 0, 0, 0, 24, 14, 18, 43, 31, 33, 57, 0, 40, 0, 0, 29, 0, 9, 35, 0, 46, 0, 0, 50, 56, 0, 0, 0, 0, 0, 27, 0, 0, 0, 15, 37, 10, 0, 0, 22, 55, 0, 0, 19, 0, 0, 0, 0, 0, 42, 0, 49, 0, 25, 0, 0, 45, 11, 54, 0, 39, 0, 0
};


/* Fermat's method for inversion employing r-t-l square and multiply,
 * unrolled for actual parameters */
static inline
FQ_ELEM fq_inv(FQ_ELEM x) {
   return fq_inv_table[x];
   // FQ_ELEM xlift;
   // xlift = x;
   // FQ_ELEM accum = 1;
   // /* No need for square and mult always, Q-2 is public*/
   // uint32_t exp = Q-2;
   // while(exp) {
   //    if(exp & 1) {
   //       accum = br_red(br_mul(accum, xlift));
   //    }
   //    xlift = br_red(br_mul(xlift, xlift));
   //    exp >>= 1;
   // }
   // return accum;
} /* end fq_inv */

/// NOTE: input must be reduced, and must not be secret.
static inline
FQ_ELEM fq_square(const FQ_ELEM x) {
   return fq_square_table[x];
}

/// NOTE: input must be reduced, and must not be secret.
/// Returns 0 if 0 or doesn't exist! Might change to q+1
static inline
FQ_ELEM fq_sqrt(const FQ_ELEM x) {
   return fq_sqrt_table[x];
}

/* Sampling functions from the global TRNG state */

DEF_RAND(fq_star_rnd_elements, FQ_ELEM, 1, Q-1)

DEF_RAND(rand_range_q_elements, FQ_ELEM, 0, Q-1)

/* Sampling functions from the taking the PRNG state as a parameter*/
DEF_RAND_STATE(fq_star_rnd_state_elements, FQ_ELEM, 1, Q-1)

DEF_RAND_STATE(rand_range_q_state_elements, FQ_ELEM, 0, Q-1)

#include "macro.h"

/// NOTE: these functions are outsourced to this file, to make the
/// optimizied implementation as easy as possible.
/// accumulates a row
/// \param d
/// \return sum(d) for _ in range(N-K)
static inline
FQ_ELEM row_acc(const FQ_ELEM *d) {
    vec256_t s, t, c01, c7f;
    vset8(s, 0);
    vset8(c01, 0x01);
    vset8(c7f, 0x7F);

    for (uint32_t col = 0; col < N_K_pad; col+=32) {
        vload256(t, (const vec256_t *)(d + col));
        vadd8(s, s, t);
        //barrett_red8(s, t, c7f, c01);
        W_RED127_(s);
	 }

    uint32_t k = vhadd8(s);
    return fq_red(k);
}

/// accumulates the inverse of a row
/// \param d
/// \return sum(d[i]**-1) for i in range(N-K)
static inline
FQ_ELEM row_acc_inv(const FQ_ELEM *d) {
    // NOTE: actually only the last pos need to be 0
    static FQ_ELEM inv_data[N_K_pad] = {0}; 
    for (uint32_t col = 0; col < (N-K); col++) {
        inv_data[col] = fq_inv(d[col]);
	}

    return row_acc(inv_data);
}

/// scalar multiplication of a row
/// NOTE: not a full reduction
/// \param row[in/out] *= s for _ in range(N-K)
/// \param s
static inline
void row_mul(FQ_ELEM *row, const FQ_ELEM s) {
    vec256_t shuffle, t, c7f, c01, b, a, a_lo, a_hi, b_lo, b_hi;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    // precompute b
    vset8(b, s);
    vget_lo(tmp, b);
    vextend8_16(b_lo, tmp);
    vget_hi(tmp, b);
    vextend8_16(b_hi, tmp);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        vload256(a, (vec256_t *)(row + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, b_lo, t);
        barrett_mul_u16(a_hi, a_hi, b_hi, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0xd8);

        vpermute2(t, a_lo, a_hi, 0x20);

        // barrett_red8(t, r, c7f, c01);
        W_RED127_(t);
        vstore256((vec256_t *)(row + col), t);
    }
}

/// scalar multiplication of a row
/// \param out = s*in[i] for i in range(N-K)
/// \param in
/// \param s
static inline
void row_mul2(FQ_ELEM *out, const FQ_ELEM *in, const FQ_ELEM s) {
    vec256_t shuffle, t, c7f, c01, b, a, a_lo, a_hi, b_lo, b_hi;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    // precompute b
    vset8(b, s);
    vget_lo(tmp, b);
    vextend8_16(b_lo, tmp);
    vget_hi(tmp, b);
    vextend8_16(b_hi, tmp);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        vload256(a, (vec256_t *)(in + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, b_lo, t);
        barrett_mul_u16(a_hi, a_hi, b_hi, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0xd8);

        vpermute2(t, a_lo, a_hi, 0x20);

        // barrett_red8(t, r, c7f, c01);
        W_RED127_(t);
        vstore256((vec256_t *)(out + col), t);
    }
}

///
/// \param out = in1[i]*in2[i] for i in range(N-K)
/// \param in1
/// \param in2
static inline
void row_mul3(FQ_ELEM *out, const FQ_ELEM *in1, const FQ_ELEM *in2) {
    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi, b, b_lo, b_hi;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        vload256(a, (vec256_t *)(in1 + col));
        vload256(b, (vec256_t *)(in2 + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);
        vget_lo(tmp, b);
        vextend8_16(b_lo, tmp);
        vget_hi(tmp, b);
        vextend8_16(b_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, b_lo, t);
        barrett_mul_u16(a_hi, a_hi, b_hi, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0xd8);

        vpermute2(t, a_lo, a_hi, 0x20);

        // barrett_red8(t, r, c7f, c01);
        W_RED127_(t);
        vstore256((vec256_t *)(out + col), t);
    }
}

// TODO: Add AVX2
/// sum of rows
/// \param out[i] = out[i] + s*in[i] for i in range(N-K)
/// \param in
/// \param s
static inline
void row_sum(FQ_ELEM *out, const FQ_ELEM *in, const FQ_ELEM s, uint8_t c) {
    for(uint8_t i = 0; i<c; i++){
        out[i] = fq_add(out[i],fq_mul(in[i],s));
    }
}

// TODO: Add AVX2
// Inner product of a row
// \param out = sum(in[i]*in[i] for i in range(K))
// \param in
// \param s
static inline
/*
void inner_prod(FQ_ELEM *out, const FQ_ELEM *in) {
    *out = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        *out = fq_add(*out,fq_mul(in[col], in[col]));
    }
}
*/
void inner_prod(FQ_ELEM *out, const FQ_ELEM *in) {
    *out = 0;
    FQ_ELEM tmp[K_pad] = {0};
    row_mul3(tmp,in,in);
    *out=row_acc(tmp);
}

// TODO: Add AVX2
/// Scalar product of two row
/// \param out = sum(in1[i]*in2[i] for i in range(K))
/// \param in
/// \param s
static inline
void scalar_prod(FQ_ELEM *out, const FQ_ELEM *in1, const FQ_ELEM *in2) {
    *out = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        *out = fq_add(*out,fq_mul(in1[col], in2[col]));
    }
}

/// invert a row
/// \param out[out]: in[i]**-1 for i in range(N-K)
/// \param in [in]
static inline
void row_inv2(FQ_ELEM *out, const FQ_ELEM *in) {
    for (uint32_t col = 0; col < (N-K); col++) {
        out[col] = fq_inv(in[col]);
    }
}

/// NOTE: avx512 optimized version (it has a special instruction for stuff like this)
/// \param in[in]: vector of length N-K
/// \return 1 if all elements are the same
///         0 else
static inline
uint32_t row_all_same(const FQ_ELEM *in) {
    vec256_t t1, t2, acc;
    vset8(acc, -1);
    vset8(t2, in[0]);

    uint32_t col = 0;
    for (; col < N_K_pad-32; col += 32) {
        vload256(t1, (vec256_t *)(in + col));
        vcmp8(t1, t1, t2);
        vand(acc, acc, t1);
    }

    const uint32_t t3 = (uint32_t)vmovemask8(acc);
    for (;col < N-K; col++) {
        if (in[col-1] != in[col]) {
            return 0;
        }
    }

    return t3 == -1u;
}

/// \param in[in] row
/// \return 1 if a zero was found
///         0 else
static inline
uint32_t row_contains_zero(const FQ_ELEM *in) {
    vec256_t t1, t2, acc;
    vset8(t2, 0);
    vset8(acc, 0);
    uint32_t col = 0;
    for (; col < (N_K_pad-32); col += 32) {
        vload256(t1, (vec256_t *)(in + col));
        vcmp8(t1, t1, t2);
        vor(acc, acc, t1);
    }
    
    const uint32_t t3 = (uint32_t)vmovemask8(acc);
    if (t3 != 0ul) { return 1; }

    for (;col < N-K; col++) {
        if (in[col] == 0) {
            return 1;
        }
    }
    return 0;
}

/// \param in[in]: vector of length N-K
/// \return the number of zeros in the input vector
static inline
uint32_t row_count_zero(const FQ_ELEM *in) {
    vec256_t t1, zero, acc, mask;
    vset8(zero, 0);
    vset8(acc, 0);
    vset8(mask, 1);
    uint32_t col = 0;
    for (; col < (N_K_pad-32); col += 32) {
        vload256(t1, (vec256_t *)(in + col));
        vcmp8(t1, t1, zero);
        vand(t1, t1, mask);
        vadd8(acc, acc, t1);
    }
  
    uint32_t a = vhadd8(acc);
    for (;col < N-K; col++) {
        a += (in[col] == 0);
    }
    return a;
}

// TODO: Add AVX2
static inline
void anti_normalize(FQ_ELEM c[K_pad]){
    FQ_ELEM in_prod;
    inner_prod(&in_prod, c);
    FQ_ELEM root = fq_sqrt(fq_inv(fq_sub(0,in_prod)));

    if(root != 0){
        row_mul(c,root);
    }
}
