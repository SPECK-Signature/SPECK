/**
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

#include "parameters.h"
#include "rng.h"
#include "macro.h"

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
      for (unsigned i = 0; i < ((sizeof(WORD_T)*8) / REQ_BITS); i++) { \
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
      for (unsigned i = 0; i < ((sizeof(WORD_T)*8) / REQ_BITS); i++) { \
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
    return fq_red((FQ_DOUBLEPREC) x * (FQ_DOUBLEPREC) y);
}

static inline
FQ_ELEM fq_add(const FQ_ELEM x, const FQ_ELEM y) {
    return (x + y) % Q;
}

/// NOTE: maybe don't use it for sensetive data
static const uint8_t fq_inv_table[128] __attribute__((aligned(64))) = {
   0, 1, 64, 85, 32, 51, 106, 109, 16, 113, 89, 104, 53, 88, 118, 17, 8, 15, 120, 107, 108, 121, 52, 116, 90, 61, 44, 80, 59, 92, 72, 41, 4, 77, 71, 98, 60, 103, 117, 114, 54, 31, 124, 65, 26, 48, 58, 100, 45, 70, 94, 5, 22, 12, 40, 97, 93, 78, 46, 28, 36, 25, 84, 125, 2, 43, 102, 91, 99, 81, 49, 34, 30, 87, 115, 105, 122, 33, 57, 82, 27, 69, 79, 101, 62, 3, 96, 73, 13, 10, 24, 67, 29, 56, 50, 123, 86, 55, 35, 68, 47, 83, 66, 37, 11, 75, 6, 19, 20, 7, 112, 119, 110, 9, 39, 74, 23, 38, 14, 111, 18, 21, 76, 95, 42, 63, 126, 0
};

static const uint8_t fq_square_table[128] __attribute__((aligned(64))) = {
0, 1, 4, 9, 16, 25, 36, 49, 64, 81, 100, 121, 17, 42, 69, 98, 2, 35, 70, 107, 19, 60, 103, 21, 68, 117, 41, 94, 22, 79, 11, 72, 8, 73, 13, 82, 26, 99, 47, 124, 76, 30, 113, 71, 31, 120, 84, 50, 18, 115, 87, 61, 37, 15, 122, 104, 88, 74, 62, 52, 44, 38, 34, 32, 32, 34, 38, 44, 52, 62, 74, 88, 104, 122, 15, 37, 61, 87, 115, 18, 50, 84, 120, 31, 71, 113, 30, 76, 124, 47, 99, 26, 82, 13, 73, 8, 72, 11, 79, 22, 94, 41, 117, 68, 21, 103, 60, 19, 107, 70, 35, 2, 98, 69, 42, 17, 121, 100, 81, 64, 49, 36, 25, 16, 9, 4, 1
};

static const uint8_t fq_sqrt_table[128] __attribute__((aligned(64))) = {
0, 1, 16, 0, 2, 0, 0, 0, 32, 3, 0, 30, 0, 34, 0, 53, 4, 12, 48, 20, 0, 23, 28, 0, 0, 5, 36, 0, 0, 0, 41, 44, 63, 0, 62, 17, 6, 52, 61, 0, 0, 26, 13, 0, 60, 0, 0, 38, 0, 7, 47, 0, 59, 0, 0, 0, 0, 0, 0, 0, 21, 51, 58, 0, 8, 0, 0, 0, 24, 14, 18, 43, 31, 33, 57, 0, 40, 0, 0, 29, 0, 9, 35, 0, 46, 0, 0, 50, 56, 0, 0, 0, 0, 0, 27, 0, 0, 0, 15, 37, 10, 0, 0, 22, 55, 0, 0, 19, 0, 0, 0, 0, 0, 42, 0, 49, 0, 25, 0, 0, 45, 11, 54, 0, 39, 0, 0
};

static const uint8_t anti_normalize_table[128] __attribute__((aligned(64))) = {
0, 0, 0, 13, 0, 40, 23, 48, 0, 0, 61, 0, 57, 0, 3, 0, 0, 0, 0, 0, 20, 0, 0, 30, 52, 0, 0, 38, 24, 17, 0, 0, 0, 47, 0, 0, 0, 0, 0, 34, 33, 0, 0, 58, 0, 29, 14, 0, 35, 0, 0, 54, 0, 49, 50, 41, 62, 7, 9, 37, 0, 0, 0, 16, 0, 46, 5, 6, 0, 0, 0, 0, 0, 0, 0, 28, 0, 27, 18, 0, 10, 0, 0, 36, 0, 39, 44, 0, 0, 25, 22, 21, 15, 43, 0, 2, 26, 31, 0, 0, 0, 60, 51, 0, 0, 59, 11, 0, 19, 45, 53, 32, 12, 0, 56, 0, 55, 0, 42, 4, 0, 0, 0, 63, 0, 8, 1};


static const uint8_t opp_table[128] __attribute__((aligned(64))) = {
0, 126, 125, 124, 123, 122, 121, 120, 119, 118, 117, 116, 115, 114, 113, 112, 111, 110, 109, 108, 107, 106, 105, 104, 103, 102, 101, 100, 99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88, 87, 86, 85, 84, 83, 82, 81, 80, 79, 78, 77, 76, 75, 74, 73, 72, 71, 70, 69, 68, 67, 66, 65, 64, 63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};


static inline
FQ_ELEM fq_opp(const FQ_ELEM x) {
    return opp_table[x];
}


/// NOTE: input must be reduced, and must not be secret.
static inline
FQ_ELEM fq_inv(const FQ_ELEM x) {
   return fq_inv_table[x];
}

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

static inline
FQ_ELEM fq_pow(FQ_ELEM x, FQ_ELEM exp) {
   FQ_DOUBLEPREC xlift;
   xlift = x;
   FQ_DOUBLEPREC accum = 1;
   /* No need for square and mult always, Q-2 is public*/
   while(exp) {
      if(exp & 1) {
         accum = fq_red(accum*xlift);
      }
      xlift = fq_red(xlift*xlift);
      exp >>= 1;
   }
   return fq_red(accum);
} /* end fq_pow */

/* Sampling functions from the global TRNG state */

DEF_RAND(fq_star_rnd_elements, FQ_ELEM, 1, Q-1)

DEF_RAND(rand_range_q_elements, FQ_ELEM, 0, Q-1)

/* Sampling functions from the taking the PRNG state as a parameter*/
DEF_RAND_STATE(fq_star_rnd_state_elements, FQ_ELEM, 1, Q-1)

DEF_RAND_STATE(rand_range_q_state_elements, FQ_ELEM, 0, Q-1)

/// NOTE: these functions are outsourced to this file, to make the
/// optimizied implementation as easy as possible.
/// accumulates a row
/// \param d
/// \return sum(d) for _ in range(N-K)
static inline
FQ_ELEM row_acc_old(const FQ_ELEM *d) {
    FQ_ELEM s = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        s = fq_add(s, d[col]);
	 }

    return s;
}

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
    W_RED127_(s);

    uint32_t k = vhadd8(s);
    return fq_red(k);
}


/// accumulates the inverse of a row
/// \param d
/// \return sum(d) for _ in range(N-K)
static inline
FQ_ELEM row_acc_inv(const FQ_ELEM *d) {
    FQ_ELEM s = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        s = fq_add(s, fq_inv(d[col]));
	 }

    return s;
}

/// scalar multiplication of a row
/// /param row[in/out] *= s for _ in range(N-K)
/// /param s
static inline
void row_mul_old(FQ_ELEM *row, const FQ_ELEM s) {
    for (uint32_t col = 0; col < (K); col++) {
        row[col] = fq_mul(s, row[col]);
    }
}

/// scalar multiplication of a row
/// NOTE: not a full reduction
/// \param row[in/out] *= s for _ in range(N-K)
/// \param s
static inline
void row_mul(FQ_ELEM *row, const FQ_ELEM s) {
    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi, b;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    vset17(b,(short)s);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        vload256(a, (vec256_t *)(row + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, b, t);
        barrett_mul_u16(a_hi, a_hi, b, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        //vpermute_4x64(a_hi, a_hi, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0x87);

        //vpermute2(t, a_lo, a_hi, 0x20);
        t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

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
    for (uint32_t col = 0; col < (K); col++) {
        out[col] = fq_mul(s, in[col]);
    }
}

/// \param out = in1[i]*in2[i] for i in range(N-K)
/// \param in1
/// \param in2
static inline
void row_mul3(FQ_ELEM *out, const FQ_ELEM *in1, const FQ_ELEM *in2) {
    for (uint32_t col = 0; col < (N-K); col++) {
        out[col] = fq_mul(in1[col], in2[col]);
    }
}

/// \param out = in1[i]*in2[i] for i in range(N-K)
/// \param in1
/// \param in2
static inline
void row_mul3_avx2(FQ_ELEM *out, const FQ_ELEM *in1, const FQ_ELEM *in2) {
    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi, b, b_lo, b_hi, res;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);
    vset8(res, 0);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        for(uint32_t row = 1; row < K; row+=1){
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
            vpermute_4x64(a_hi, a_hi, 0x87);

            t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

            W_RED127_(t);

            vadd8(res,res,t);
        }
        vstore256((vec256_t *)(out + col), t);
    }
}

/// sum of rows
/// \param out[i] = out[i] + s*in[i] for i in range(N-K)
/// \param in
/// \param s
static inline
void row_sum_old(FQ_ELEM *out, const FQ_ELEM *in, const FQ_ELEM s, uint8_t c) {
    for(uint8_t i = 0; i<c; i++){
        out[i] = fq_add(out[i],fq_mul(in[i],s));
    }
}

static inline
void row_sum(FQ_ELEM *out, const FQ_ELEM *in, const FQ_ELEM s, uint8_t c) {

    // res1 = in*s (row_mul)
    // res2 = out + res1 (vadd)
    // (a mix of these 2)

    // ROW MUL 
    vec256_t shuffle, t, c7f, c01, b, a, a_lo, a_hi;
    vec128_t tmp;

    vec256_t in1;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    // precompute b
    vset17(b,s);

    for (uint32_t col = 0; (col+32) <= NEXT_MULTIPLE(c,32); col+=32) {
        vload256(a, (vec256_t *)(in + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, b, t);
        barrett_mul_u16(a_hi, a_hi, b, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0x87);

        t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

        // barrett_red8(t, r, c7f, c01);
        W_RED127_(t);
        vload256(in1, (vec256_t *)(out + col));

        vadd8(in1,in1,t);
        W_RED127_(in1);

        vstore256((vec256_t *)(out + col), in1);
    }
}

/// Inner product of a row
/// \param out = sum(in[i]*in[i] for i in range(K))
/// \param in
/// \param s
static inline
void inner_prod_old(FQ_ELEM *out, const FQ_ELEM *in) {
    *out = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        *out = fq_add(*out,fq_mul(in[col], in[col]));
    }
}

/// Inner product of a row
/// \param out = sum(in[i]*in[i] for i in range(K))
/// \param in
/// \param s
static inline
void inner_prod(FQ_ELEM *out, const FQ_ELEM *in) {

    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi;
    vec128_t tmp;

    vload256(shuffle, (vec256_t *) shuff_low_half);
    vset8(c7f, 127);
    vset8(c01, 1);

    vec256_t s;
    vset8(s, 0);

    for (uint32_t col = 0; (col+32) <= N_K_pad; col+=32) {
        vload256(a, (vec256_t *)(in + col));

        vget_lo(tmp, a);
        vextend8_16(a_lo, tmp);
        vget_hi(tmp, a);
        vextend8_16(a_hi, tmp);

        barrett_mul_u16(a_lo, a_lo, a_lo, t);
        barrett_mul_u16(a_hi, a_hi, a_hi, t);

        vshuffle8(a_lo, a_lo, shuffle);
        vshuffle8(a_hi, a_hi, shuffle);

        vpermute_4x64(a_lo, a_lo, 0xd8);
        vpermute_4x64(a_hi, a_hi, 0x87);

        t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

        // barrett_red8(t, r, c7f, c01);
        W_RED127_(t);
        vadd8(s, s, t);
        W_RED127_(s);

        // Accumulate t!
    }
    
    uint32_t k = vhadd8(s);
    *out = fq_red(k);
}

static inline
uint8_t anti_normalize(FQ_ELEM c[K_pad]){
    FQ_ELEM in_prod;
    inner_prod(&in_prod, c);
    //FQ_ELEM root = fq_sqrt(fq_inv(fq_sub(0,in_prod)));
    FQ_ELEM root = anti_normalize_table[in_prod];

    if(root != 0){
        row_mul(c,root);
        return 1;
    }else{
        return 0;
    }
}
