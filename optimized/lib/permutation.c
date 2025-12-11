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
#include "permutation.h"
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"
#include <string.h>

///
#define POS_BITS BITS_TO_REPRESENT(N-1)

///
#define POS_MASK (((POSITION_T) 1 << POS_BITS) - 1)

/// applies a random permutation between [0, n-1] on the
/// input permutation
/// \param shake_monomial_state[in/out]:
/// \param permutation[in/out]: random permutation. Must be initialized with
///         [0,....,n-1]
/// \param n <= N: number of elements in the permutation
void yt_shuffle_state_limit(SHAKE_STATE_STRUCT *shake_monomial_state,
                            POSITION_T *permutation,
                            const uint32_t n) {
    uint32_t rand_u32[N] = {0};
    POSITION_T tmp;

    csprng_randombytes((unsigned char *) &rand_u32, sizeof(uint32_t)*n, shake_monomial_state);
    for (size_t i = 0; i < n - 1; ++i) {
        rand_u32[i] = i + rand_u32[i] % (n - i);
    }

    for (size_t i = 0; i < n - 1; ++i) {
        tmp = permutation[i];
        permutation[i] = permutation[rand_u32[i]];
        permutation[rand_u32[i]] = tmp;
    }
}

/// \param shake_monomial_state[in/out]:
/// \param permutation[in/out]: random permutation. Must be initialized with
///         [0,....,n-1]
void yt_shuffle_state(SHAKE_STATE_STRUCT *shake_monomial_state, POSITION_T permutation[N]) {
   uint64_t rand_u64;
   POSITION_T tmp;
   POSITION_T x;
   int c;

   csprng_randombytes((unsigned char *) &rand_u64,
                             sizeof(rand_u64),
                             shake_monomial_state);
   c = 0;

   for (int i = 0; i < N; i++) {
      do {
         if (c == (64/POS_BITS)-1) {
            csprng_randombytes((unsigned char *) &rand_u64,
                                sizeof(rand_u64),
                                shake_monomial_state);
            c = 0;
         }
         x = rand_u64 & (POS_MASK);
         rand_u64 = rand_u64 >> POS_BITS;
         c = c + 1;
      } while (x >= N);

      tmp = permutation[i];
      permutation[i] = permutation[x];
      permutation[x] = tmp;
   } 
}
/* FY shuffle on the permutation, sampling from the global TRNG state */
void yt_shuffle(POSITION_T permutation[N]) {
    yt_shuffle_state(&platform_csprng_state, permutation);
}


/// expands a monomial matrix, given a double length PRNG seed (used to prevent
/// multikey attacks)
/// \param res[out]: the randomly sampled permutation vector 
/// \param seed[in]: the seed
void permutation_sample_prikey(permutation_t *res,
                            const unsigned char seed[PRIVATE_KEY_SEED_LENGTH_BYTES]) {
    SHAKE_STATE_STRUCT shake_monomial_state = {0};
    initialize_csprng(&shake_monomial_state, seed, PRIVATE_KEY_SEED_LENGTH_BYTES);
    for (uint32_t i = 0; i < N; i++) {
        res->values[i] = i;
    }
    /* FY shuffle on the permutation */
    yt_shuffle_state(&shake_monomial_state, res->values);
} 

/// \param res[out]: = to_invert**-1
/// \param to_invert[in]: permutation to invert
//void generate_final_perm(permutation_t *res, const permutation_t *const perm1) {
//    for(uint32_t i = 0; i < N; i++) {
//        res->permutation[perm2->permutation[i]] = i;
//    }
//}

/// \param res[out]: = to_invert**-1
/// \param to_invert[in]: permutation to invert
void permutation_inv(permutation_t *res, const permutation_t *const to_invert) {
    for(uint32_t i = 0; i < N; i++) {
        res->values[to_invert->values[i]] = i;
    }
}

/* expands a permutation, given a PRNG seed and a salt (used for ephemeral
 * permutations) */
void word_permutation_sample_salt(
                          FQ_ELEM u[K],
                          permutation_t *res,
                          const unsigned char seed[SEED_LENGTH_BYTES],
                          const unsigned char salt[HASH_DIGEST_LENGTH],
                          const uint16_t round_index) {
    SHAKE_STATE_STRUCT shake_monomial_state = {0};
    const int shake_buffer_len = SEED_LENGTH_BYTES + HASH_DIGEST_LENGTH + sizeof(uint16_t);
    uint8_t shake_input_buffer[shake_buffer_len];
    memcpy(shake_input_buffer, seed, SEED_LENGTH_BYTES);
    memcpy(shake_input_buffer + SEED_LENGTH_BYTES, salt, HASH_DIGEST_LENGTH);
    memcpy(shake_input_buffer + SEED_LENGTH_BYTES + HASH_DIGEST_LENGTH, &round_index, sizeof(uint16_t));

    initialize_csprng(&shake_monomial_state, shake_input_buffer, shake_buffer_len);
    fq_star_rnd_state_elements(&shake_monomial_state, u, K);
    for (uint32_t i = 0; i < N; i++) {
        res->values[i] = i;
    }
    /* FY shuffle on the permutation */
    yt_shuffle_state(&shake_monomial_state, res->values);
} /* end monomial_mat_seed_expand */

void word_sample_salt(FQ_ELEM u[K],
                      const unsigned char seed[SEED_LENGTH_BYTES],
                      const unsigned char salt[HASH_DIGEST_LENGTH],
                      const uint16_t round_index) {
    SHAKE_STATE_STRUCT shake_monomial_state = {0};
    const int shake_buffer_len = SEED_LENGTH_BYTES + HASH_DIGEST_LENGTH + sizeof(uint16_t);
    uint8_t shake_input_buffer[shake_buffer_len];
    memcpy(shake_input_buffer, seed, SEED_LENGTH_BYTES);
    memcpy(shake_input_buffer + SEED_LENGTH_BYTES, salt, HASH_DIGEST_LENGTH);
    memcpy(shake_input_buffer + SEED_LENGTH_BYTES + HASH_DIGEST_LENGTH, &round_index, sizeof(uint16_t));

    initialize_csprng(&shake_monomial_state, shake_input_buffer, shake_buffer_len);
    fq_star_rnd_state_elements(&shake_monomial_state, u, K);
} /* end monomial_mat_seed_expand */
