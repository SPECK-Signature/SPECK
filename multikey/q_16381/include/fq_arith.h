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
#include "lut.h"

#define NUM_BITS_Q (BITS_TO_REPRESENT(Q))
#define COND_SUB_SHIFT (8*sizeof(FQ_ELEM)-1)


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
    FQ_ELEM mask = -(sub_q >> COND_SUB_SHIFT);
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


static inline
FQ_ELEM fq_inv(const FQ_ELEM x) {
   return fq_inv_table[x];
}

static inline
FQ_ELEM fq_square(const FQ_ELEM x) {
   return fq_square_table[x];
}

static inline
FQ_ELEM fq_sqrt(const FQ_ELEM x) {
   return fq_sqrt_table[x];
}

static inline
FQ_ELEM fq_opp(const FQ_ELEM x) {
   return fq_opp_table[x];
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

DEF_RAND(rand_range_K_elements, uint8_t, 0, K-1)
DEF_RAND_STATE(rand_range_K_state_elements, uint8_t, 0, K-1)
DEF_RAND_STATE(rand_range_chal_state_elements, uint8_t, 0, NUM_KEYPAIRS-1)

static inline
FQ_ELEM row_acc_old(const FQ_ELEM *d) {
    FQ_ELEM s = 0;
    for (uint32_t col = 0; col < (N-K); col++) {
        s = fq_add(s, d[col]);
	 }

    return s;
}

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


/// \param out = in1[i]*in2[i] for i in range(N-K)
/// \param in1
/// \param in2
static inline
void row_mul3_normal(FQ_ELEM *out, const FQ_ELEM *in1, const FQ_ELEM *in2) {
    for (uint32_t col = 0; col < (N-K); col++) {
        out[col] = fq_mul(in1[col], in2[col]);
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


static inline
void row_mul3(uint16_t* out, uint16_t* in1, uint16_t* in2) {

    __m256i diff, mask, a, b, low16, high12, low16_hi2;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    for(uint16_t i=0; i<N_pad; i=i+16){
         a = _mm256_loadu_si256((const __m256i *)(in1 + i));
         b = _mm256_loadu_si256((const __m256i *)(in2 + i));

        low16 = _mm256_mullo_epi16(a, b); 
        high12 = _mm256_mulhi_epu16(a, b); 

        low16_hi2 = _mm256_and_si256(low16,hi2_mask);
        low16 = _mm256_sub_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
        low16 = _mm256_add_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
        low16 = _mm256_add_epi16(low16,low16_hi2);

        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

        diff = _mm256_subs_epu16(low16,c2q);
        mask = _mm256_cmpgt_epi16(diff, c0);
        low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

        mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
        low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

        _mm256_storeu_si256((__m256i *)(out + i), low16);
    }
}

static inline
void inner_prod(uint16_t* out, uint16_t* in1, uint16_t* in2) {

    uint32_t sum = 0;
        
    __m256i diff, mask, a, b, low16, high12, low16_hi2;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    for(uint16_t i=0; i<N_K_pad; i=i+16){
         a = _mm256_loadu_si256((const __m256i *)(in1 + i));
         b = _mm256_loadu_si256((const __m256i *)(in2 + i));

        low16 = _mm256_mullo_epi16(a, b); 
        high12 = _mm256_mulhi_epu16(a, b); 

        low16_hi2 = _mm256_and_si256(low16,hi2_mask);
        low16 = _mm256_sub_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
        low16 = _mm256_add_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
        low16 = _mm256_add_epi16(low16,low16_hi2);

        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

        diff = _mm256_subs_epu16(low16,c2q);
        mask = _mm256_cmpgt_epi16(diff, c0);
        low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

        mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
        low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

        //accumulate
        a = _mm256_srli_epi32(low16, 16);
        b = _mm256_add_epi16(a, low16);

        a = _mm256_srli_epi64(b, 32);
        b = _mm256_add_epi16(a, b);

        //a = _mm256_srli_si256(b, 8);
        //b = _mm256_add_epi16(a, b);

        sum += _mm256_extract_epi16(b, 0);
        sum += _mm256_extract_epi16(b, 4); 
        sum += _mm256_extract_epi16(b, 8);
        sum += _mm256_extract_epi16(b, 12); 
    }

    sum = 3*(sum >> 14) + (sum&16383);
    sum = sum - 49143;
    sum = ((-(sum>>31))&16381) + sum;
    sum = ((-(sum>>31))&16381) + sum;
    sum = ((-(sum>>31))&16381) + sum;

    *out = (uint16_t) sum;
}

/// \return in[0] + in[1] + ... + in[15] % q
static inline uint16_t acc_vec(const __m256i in) {

    __m256i a = _mm256_srli_epi32(in, 16);
    __m256i t = _mm256_add_epi16(a, in);

    a = _mm256_srli_epi64(t, 32);
    t = _mm256_add_epi16(a, t);

    a = _mm256_srli_si256(t, 8);
    t = _mm256_add_epi16(a, t);

    uint32_t r = _mm256_extract_epi16(t, 8) + _mm256_extract_epi16(t, 0); 


    return r;
}

static inline
void row_mul(uint16_t* out, uint16_t* in, uint16_t s) {

    __m256i diff, mask, a, b, low16, high12, low16_hi2;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    b = _mm256_set1_epi16(s);

    for(uint16_t i=0; i<N-K; i=i+16){
         a = _mm256_loadu_si256((const __m256i *)(in + i));

        low16 = _mm256_mullo_epi16(a, b); 
        high12 = _mm256_mulhi_epu16(a, b); 

        low16_hi2 = _mm256_and_si256(low16,hi2_mask);
        low16 = _mm256_sub_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
        low16 = _mm256_add_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
        low16 = _mm256_add_epi16(low16,low16_hi2);

        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

        diff = _mm256_subs_epu16(low16,c2q);
        mask = _mm256_cmpgt_epi16(diff, c0);
        low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

        mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
        low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

        _mm256_storeu_si256((__m256i *)(out + i), low16);
    }
}

static inline
void row_mul_full(uint16_t* out, uint16_t* in, uint16_t s) {

    __m256i diff, mask, a, b, low16, high12, low16_hi2;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    b = _mm256_set1_epi16(s);

    for(uint16_t i=0; i<N; i=i+16){
         a = _mm256_loadu_si256((const __m256i *)(in + i));

        low16 = _mm256_mullo_epi16(a, b); 
        high12 = _mm256_mulhi_epu16(a, b); 

        low16_hi2 = _mm256_and_si256(low16,hi2_mask);
        low16 = _mm256_sub_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
        low16 = _mm256_add_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
        low16 = _mm256_add_epi16(low16,low16_hi2);

        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

        diff = _mm256_subs_epu16(low16,c2q);
        mask = _mm256_cmpgt_epi16(diff, c0);
        low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

        mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
        low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

        _mm256_storeu_si256((__m256i *)(out + i), low16);
    }
}


static inline
void row_sum(uint16_t* out, uint16_t* in, uint16_t s, uint16_t c) {

    __m256i diff, mask, a, b, low16, high12, low16_hi2, out_vec;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i cqm1 = _mm256_set1_epi16(16380);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    b = _mm256_set1_epi16(s);

    for(uint16_t i=0; (i+16) <= NEXT_MULTIPLE(c,16); i=i+16){
         a = _mm256_loadu_si256((const __m256i *)(in + i));

        low16 = _mm256_mullo_epi16(a, b); 
        high12 = _mm256_mulhi_epu16(a, b); 

        low16_hi2 = _mm256_and_si256(low16,hi2_mask);
        low16 = _mm256_sub_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
        low16 = _mm256_add_epi16(low16,low16_hi2);
        low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
        low16 = _mm256_add_epi16(low16,low16_hi2);

        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
        low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

        diff = _mm256_subs_epu16(low16,c2q);
        mask = _mm256_cmpgt_epi16(diff, c0);
        low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

        mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
        low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

        out_vec = _mm256_loadu_si256((const __m256i *)(out + i));
        out_vec = _mm256_add_epi16(out_vec,low16);

        mask = _mm256_cmpgt_epi16(out_vec, cqm1); // compare greater: 0xffff ? 0x0000
        out_vec = _mm256_sub_epi16(out_vec, _mm256_and_si256(mask, cq));

        _mm256_storeu_si256((__m256i *)(out + i), out_vec);
    }
}

static inline
uint8_t anti_normalize(uint16_t c[N_K_pad]){
    FQ_ELEM in_prod;
    inner_prod(&in_prod, c, c);

    //FQ_ELEM root = fq_sqrt(fq_inv(fq_sub(0,in_prod)));
    FQ_ELEM root = anti_normalize_table[in_prod];

    if(root != 0){
        row_mul(c,c,root);
        return 1;
    }else{
        return 0;
    }
}

static inline
void row_mat_mult(FQ_ELEM *out,
                    const FQ_ELEM *vec,
                    uint16_t mat_rows,
                    uint16_t mat_cols_padded,
                    const FQ_ELEM M[mat_rows][mat_cols_padded],
                    uint16_t r,
                    uint16_t c){

    __m256i diff, mask, a, b, low16, high12, low16_hi2, out_vec,res;
    __m256i c0 = _mm256_setzero_si256();
    __m256i cq = _mm256_set1_epi16(16381);
    __m256i cqm1 = _mm256_set1_epi16(16380);
    __m256i c2q = _mm256_set1_epi16(32762);
    __m256i hi2_mask = _mm256_set1_epi16(0xc000);

    for (uint32_t col = 0; (col+16) <= NEXT_MULTIPLE(c, 16); col+=16) {
        // precompute 
        
        //res = _mm256_set1_epi16(0);
        res = _mm256_setzero_si256();

        for (uint32_t row = 0; row < r; row+=1){

            a = _mm256_loadu_si256( (const __m256i*) &M[row][col]);
            b = _mm256_set1_epi16(vec[row]);

            low16 = _mm256_mullo_epi16(a, b); 
            high12 = _mm256_mulhi_epu16(a, b); 

            low16_hi2 = _mm256_and_si256(low16,hi2_mask);
            low16 = _mm256_sub_epi16(low16,low16_hi2);
            low16_hi2 = _mm256_srli_epi16(low16_hi2,13);
            low16 = _mm256_add_epi16(low16,low16_hi2);
            low16_hi2 = _mm256_srli_epi16(low16_hi2,1);
            low16 = _mm256_add_epi16(low16,low16_hi2);

            low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,2));
            low16 = _mm256_add_epi16(low16,_mm256_slli_epi16(high12,3));

            diff = _mm256_subs_epu16(low16,c2q);
            mask = _mm256_cmpgt_epi16(diff, c0);
            low16 = _mm256_sub_epi16(low16,_mm256_and_si256(mask,c2q));

            mask = _mm256_cmpgt_epi16(low16, cq); // compare greater: 0xffff ? 0x0000
            low16 = _mm256_sub_epi16(low16, _mm256_and_si256(mask, cq));

            // Accumulate result
            res = _mm256_add_epi16(res,low16);

            // Reduce after accumulation
            mask = _mm256_cmpgt_epi16(res, cqm1); // compare greater: 0xffff ? 0x0000
            res = _mm256_sub_epi16(res, _mm256_and_si256(mask, cq));
        }

        _mm256_storeu_si256((__m256i *)(out + col), res);
    }

}
