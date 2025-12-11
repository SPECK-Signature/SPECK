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

#include <stdint.h>

#include "parameters.h"
#include "permutation.h"
#include "string.h"

typedef struct {  /* Generator matrix, stored explicitly */
   FQ_ELEM values[K][N_pad] __attribute__((aligned(32)));
} generator_mat_t;

/* RREF Generator mat., only values and positions of non-pivot columns stored */
typedef struct {
   FQ_ELEM values[K][N_K_pad];     /* values of the non-pivot columns    */
   POSITION_T column_pos[N_K_pad]; /* positions of the non-pivot columns */
} rref_generator_mat_t;

/* RREF Generator mat., only values and positions of non-pivot columns stored */
typedef struct {
   FQ_ELEM values[K][N_K_pad];     /* values of the non-pivot columns    */
   POSITION_T column_pos[N_K_pad]; /* positions of the non-pivot columns */
} rref_parity_mat_t;

/* Set of columns not constituting the IS for an RREF matrix
 * See algorithm PrepareDigestInput in specification (V matrix)*/
typedef struct {
   FQ_ELEM values[K_pad][N_K_pad];   /* values of the non-pivot columns */
} normalized_IS_t;

/* Calculate pivot flag array */
void generator_get_pivot_flags (const rref_generator_mat_t *const G,
                                uint8_t pivot_flag [N]);

/* Memcpy row in passed A row*/
static inline
void set_row(FQ_ELEM A[K_pad], const FQ_ELEM row[K_pad]){
    memcpy(A, row, sizeof(FQ_ELEM) * K_pad);
}

void swap_columns(FQ_ELEM M[K][K_pad], uint8_t c1, uint8_t c2, uint8_t r);

void column_swap(normalized_IS_t *V,
                 const POSITION_T col1,
                 const POSITION_T col2);

/** Computes the row-reduced echelon form of the generator matrix
 *  returns 1 on success, 0 on failure, computation is done in-place
 *  Provides the positions of the pivot columns, one-hot encoded in
 *  is_pivot_column
 **/
int generator_RREF(generator_mat_t *G,
                   uint8_t is_pivot_column[N_pad]);

int generator_RREF_pivot_reuse(generator_mat_t *G,
                                 uint8_t is_pivot_column[N],
                                 uint8_t was_pivot_column[N],
                                 const int pvt_reuse_limit);

/* extracts the last N-K columns from a generator matrix, filling
 * in the compact RREF representation*/
void generator_rref_compact(rref_generator_mat_t *compact,
                            const generator_mat_t *const full,
                            const uint8_t is_pivot_column[N] );

void generator_rref_compact_speck(FQ_ELEM G[K][K_pad],
                            const generator_mat_t *const full,
                            const uint8_t is_pivot_column[N] );

void generator_to_normalized(normalized_IS_t *v,
                             const generator_mat_t *const G);

/* Compresses a columns of an IS matrix */
void compress_columns(uint8_t *compressed,
                      const normalized_IS_t *const full);

/* Compresses a generator matrix in RREF into a array of bytes */
void compress_rref(uint8_t *compressed,
                   const generator_mat_t *const full,
                   const uint8_t is_pivot_column[N]);

/* Expands a compressed RREF generator matrix into a full one */
void expand_to_rref(generator_mat_t *full,
                    const uint8_t *compressed,
                    uint8_t is_pivot_column[N]);

/* Takes as input a compact RREF generator matrix, i.e. a set of N-K
 * columns and their position in the RREF and normalizes the columns themselves
 * i.e., rescales them to obtain the leading nonzero term equal to 1, and
 * sorts them according to the lexicographic order.
 * The action is done in-place; the column_pos vector is not altered so that
 * the normalized, compacted form can be reexpanded (albeit not needed
 * in the current protocol)
 */
void generator_compact_rref_normalize(rref_generator_mat_t *compact);

/* Expands a compact representation of a generator matrix into full form*/
void generator_rref_expand(generator_mat_t *full,
                           const rref_generator_mat_t *const compact);

void antiorthogonal_sample(FQ_ELEM A[K][K_pad],
                              const unsigned char seed[SEED_LENGTH_BYTES]);

/* expands a systematic form generator from a seed randomly drawing only
 * non-identity portion */
void generator_sample(rref_generator_mat_t *res,
                              const unsigned char seed[SEED_LENGTH_BYTES]);

static inline
void row_mat_mult(FQ_ELEM *out,
                    const FQ_ELEM *vec,
                    const FQ_ELEM M[K][K_pad],
                    uint8_t r,
                    uint8_t c){

    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi, b, b_lo, b_hi;
    vec128_t tmp;
    vec256_t res;
    vset8(c7f, 127);
    vset8(c01, 1);

    vload256(shuffle, (vec256_t *) shuff_low_half);

    for (uint32_t col = 0; (col+32) <= NEXT_MULTIPLE(c, 32); col+=32) {
        // precompute 
        
        vset8(res, 0);
        //vset8(c7f, 127);
        //vset8(c01, 1);

        for (uint32_t row = 0; row < r; row+=1){
            // precompute b

            //vset8(b, vec[row]);
            //vget_lo(tmp, b);
            //vextend8_16(b_lo, tmp);
            //vget_hi(tmp, b);
            //vextend8_16(b_hi, tmp);
            vset17(b,vec[row]);

            vload256(a, (vec256_t *)(M[row]+col));

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
            //t = _mm256_blend_epi16(a_lo, a_hi, 0xff);
            t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

            // barrett_red8(t, r, c7f, c01);
            W_RED127_(t);
            vadd8(res,res,t)
            W_RED127_(res);
        }

        vstore256((vec256_t *)(out + col), res);
    }

}

static inline
void row_mat_mult_opp_tran(FQ_ELEM *out,
                    const FQ_ELEM *vec,
                    const FQ_ELEM M[K][K_pad],
                    uint8_t r,
                    uint8_t c,
                    uint8_t row_off){

    vec256_t shuffle, t, c7f, c01, a, a_lo, a_hi, b, b_lo, b_hi;
    vec128_t tmp;
    vec256_t res;
    vset8(c7f, 127);
    vset8(c01, 1);

    vload256(shuffle, (vec256_t *) shuff_low_half);

    for (uint32_t col = 0; (col+32) <= NEXT_MULTIPLE(c, 32); col+=32) {
        // precompute 
        
        vset8(res, 0);
        //vset8(c7f, 127);
        //vset8(c01, 1);

        for (uint32_t row = 0; row < r; row+=1){
            // precompute b

            //vset8(b, vec[row]);
            //vget_lo(tmp, b);
            //vextend8_16(b_lo, tmp);
            //vget_hi(tmp, b);
            //vextend8_16(b_hi, tmp);
            vset17(b,fq_opp(vec[row]));

            vload256(a, (vec256_t *)(M[row+row_off]+col));

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
            //t = _mm256_blend_epi16(a_lo, a_hi, 0xff);
            t = _mm256_blend_epi32(a_lo, a_hi, 0xf0);

            // barrett_red8(t, r, c7f, c01);
            W_RED127_(t);
            vadd8(res,res,t)
            W_RED127_(res);
        }

        vstore256((vec256_t *)(out + col), res);
    }

}

void row_mat_mult_avx2(FQ_ELEM *out,
                    const FQ_ELEM *row,
                    FQ_ELEM M[K][K_pad],
                    uint8_t r,
                    uint8_t c);

void permute_generator(generator_mat_t *res,
                        const generator_mat_t *const G,
                        const permutation_t *const perm);

void permute_codeword(FQ_ELEM res[N],
                        const FQ_ELEM to_perm[N],
                        const permutation_t *const perm);

void generate_rref_perm(permutation_t *res, uint8_t is_pivot_column[N]);


void compress_rref_speck(uint8_t *compressed,
                   const generator_mat_t *const full,
                   const uint8_t is_pivot_column[N]);

void compress_rref_speck_non_IS(uint8_t *compressed,
                                const rref_generator_mat_t *const G_rref);

void expand_to_rref_speck(rref_generator_mat_t *matr,
                    const uint8_t *compressed);

void sample_codeword_rref(FQ_ELEM c[N_pad],const rref_generator_mat_t G);

void expand_c1s(FQ_ELEM c1s[W][K_pad], const uint8_t *compressed_c1s);
void compress_c1s(uint8_t *compressed_c1s, FQ_ELEM c1s[W][K_pad]);
void row_mat_mult_old(FQ_ELEM *out,
                    const FQ_ELEM *row,
                    FQ_ELEM M[K][K_pad],
                    uint8_t r,
                    uint8_t c);
