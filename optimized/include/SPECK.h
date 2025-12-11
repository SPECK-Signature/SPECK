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
#include <stddef.h>

typedef struct __attribute__((packed)) {
#ifdef SPECK_RESAMPLE_G
   unsigned char G_0_seed[SEED_LENGTH_BYTES];
#endif
#ifdef SPECK_COMPRESS_G
   uint8_t G_0_rref [SPECK_RREF_MAT_PACKEDBYTES];
#endif
#ifdef SPECK_FULL_G
   uint8_t G_0_rref [K][K_pad];
#endif
#ifdef SPECK_COMPRESS_GP
   uint8_t SF_G [NUM_KEYPAIRS-1][SPECK_RREF_MAT_PACKEDBYTES];
#else
   uint8_t SF_G [NUM_KEYPAIRS-1][K][K_pad];
#endif
} speck_pubkey_t;

typedef struct __attribute__((packed)) {
   uint8_t permutations[NUM_KEYPAIRS-1][N];
   unsigned char sk_seed[PRIVATE_KEY_SEED_LENGTH_BYTES];
} speck_prikey_t;

typedef struct __attribute__((packed)) speck_sig_t {
    uint8_t digest[HASH_DIGEST_LENGTH];
    uint8_t salt[HASH_DIGEST_LENGTH];
    #ifdef SPECK_COMPRESS_C1S
    uint8_t c1s[SPECK_C1S_PACKEDBYTES];
    #else
    uint8_t c1s[W][K_pad];
    #endif
    uint8_t seed_storage[SEED_TREE_MAX_PUBLISHED_BYTES];
} speck_sign_t;

/* keygen cannot fail */
void SPECK_keygen(speck_prikey_t *SK,
                 speck_pubkey_t *PK);

/* sign cannot fail, but it returns the number of opened seeds */
size_t SPECK_sign(const speck_prikey_t *SK,
               const speck_pubkey_t *PK,
               const char *const m,
               const uint64_t mlen,
               speck_sign_t *sig);

/* verify returns 1 if signature is ok, 0 otherwise */
int SPECK_verify(const speck_pubkey_t *const PK,
                const char *const m,
                const uint64_t mlen,
                const speck_sign_t *const sig);
