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
#include "fq_arith.h"

typedef struct {
   POSITION_T values[N];
} permutation_t;

void yt_shuffle_state_limit(SHAKE_STATE_STRUCT *shake_monomial_state,
                            POSITION_T *permutation,
                            const uint32_t n);
void yt_shuffle_state(SHAKE_STATE_STRUCT *shake_monomial_state,
                      POSITION_T permutation[N]);
void yt_shuffle(POSITION_T permutation[N]);

void permutation_sample_prikey(permutation_t *res,
                            const unsigned char seed[PRIVATE_KEY_SEED_LENGTH_BYTES]);

void permutation_inv(permutation_t *res, const permutation_t *const to_invert);

void word_permutation_sample_salt(
                          FQ_ELEM u[K],
                          permutation_t *res,
                          const unsigned char seed[SEED_LENGTH_BYTES],
                          const unsigned char salt[HASH_DIGEST_LENGTH],
                          const uint16_t round_index);

void word_sample_salt(
                          FQ_ELEM u[K],
                          const unsigned char seed[SEED_LENGTH_BYTES],
                          const unsigned char salt[HASH_DIGEST_LENGTH],
                          const uint16_t round_index);
