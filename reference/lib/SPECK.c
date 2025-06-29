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
#include <string.h> // memcpy, memset
#include "SPECK.h"
#include "codes.h"
#include "permutation.h"
#include "parameters.h"
#include "seedtree.h"
#include "rng.h"
#include "utils.h"
#include "fips202.h"
#include "sha3.h"
#include "sort.h"

void SPECK_keygen(speck_prikey_t *SK,
                 speck_pubkey_t *PK) {
    /* generating private key from a single seed */
    
    //unsigned char secret_pk_seed[PRIVATE_KEY_SEED_LENGTH_BYTES];
    randombytes(SK->sk_seed, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* expanding it onto private seeds */
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->sk_seed, PRIVATE_KEY_SEED_LENGTH_BYTES);
    /* Generating public code G_0 */
    #ifdef SPECK_RESAMPLE_G
        csprng_randombytes(PK->G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    #else
        unsigned char G_0_seed[SEED_LENGTH_BYTES];
        csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);
    #endif

    rref_generator_mat_t G0_rref;
    #ifdef SPECK_RESAMPLE_G
        generator_sample(&G0_rref, PK->G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        generator_sample(&G0_rref, G_0_seed);
        compress_rref_speck_non_IS(PK->G_0_rref,&G0_rref);
    #endif
    #ifdef SPECK_FULL_G
        generator_sample(&G0_rref, G_0_seed);
        memcpy(PK->G_0_rref,G0_rref.values,sizeof(rref_generator_mat_t));
    #endif
 
    generator_mat_t tmp_full_G;
    generator_rref_expand(&tmp_full_G, &G0_rref);

    /* The first private key monomial is an ID matrix, no need for random
     * generation, hence NUM_KEYPAIRS-1 */
    unsigned char private_permutation_seeds[NUM_KEYPAIRS - 1][PRIVATE_KEY_SEED_LENGTH_BYTES];
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        csprng_randombytes(private_permutation_seeds[i],
                           PRIVATE_KEY_SEED_LENGTH_BYTES,
                           &sk_shake_state);
    }

    /* note that the first "keypair" is just the public generator G_0, stored
     * as a seed and the identity matrix (not stored) */
    for (uint32_t i = 0; i < NUM_KEYPAIRS - 1; i++) {
        uint8_t is_pivot_column[N_pad];
        /* expand inverse monomial from seed */
        permutation_t private_perm;
        permutation_sample_prikey(&private_perm, private_permutation_seeds[i]);

        generator_mat_t result_G;
        permute_generator(&result_G, &tmp_full_G, &private_perm);

        memset(is_pivot_column, 0, sizeof(is_pivot_column));
        generator_RREF(&result_G, is_pivot_column);

        permutation_t private_rref_perm;
        generate_rref_perm(&private_rref_perm, is_pivot_column);

        for(POSITION_T j = 0; j<N; j++){
            SK->permutations[i][j] = private_perm.values[private_rref_perm.values[j]];
        }

        #ifdef SPECK_COMPRESS_GP
            compress_rref_speck(PK->SF_G[i],&result_G,is_pivot_column);
        #else
            generator_rref_compact_speck(PK->SF_G[i],&result_G,is_pivot_column);
        #endif
    }
} /* end */

/// returns the number of opened seeds in the tree.
/// \param SK[in]: secret key
/// \param m[in]: message to sign
/// \param mlen[in]: length of the message to sign in bytes
/// \param sig[out]: signature
/// \return: x: number of leaves opened by the algorithm
size_t SPECK_sign(const speck_prikey_t *SK,
                 const speck_pubkey_t *PK,
                 const char *const m,
                 const uint64_t mlen,
                 speck_sign_t *sig) {

    /*         Private key expansion        */
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, SK->sk_seed, PRIVATE_KEY_SEED_LENGTH_BYTES);

    /* Generating seed for public code G_0 (obtained from sk_seed) */
    unsigned char G_0_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_0_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    // generate the salt from a TRNG
    randombytes(sig->salt, HASH_DIGEST_LENGTH);

    /*         Ephemeral permutations generation        */
    unsigned char ephem_permutations_seed[SEED_LENGTH_BYTES];
    randombytes(ephem_permutations_seed, SEED_LENGTH_BYTES);

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES] = {0};
    BuildGGM(seed_tree, ephem_permutations_seed, sig->salt);

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    /*         Public G_0 expansion                  */
    #ifdef SPECK_RESAMPLE_G
        rref_generator_mat_t G0_rref;
        generator_sample(&G0_rref, G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        rref_generator_mat_t G0_rref;
        expand_to_rref_speck(&G0_rref,PK->G_0_rref);
    #endif

    FQ_ELEM u[K];
    FQ_ELEM x[Q];
    FQ_ELEM codewords[T][N];

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);

    LESS_SHA3_INC_CTX state_cmt_i;
    uint8_t cmt_i[HASH_DIGEST_LENGTH];

    for (uint32_t i = 0; i < T; i++) {
        word_sample_salt(u,
                         linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                         sig->salt,
                         i);
        memcpy(codewords[i],u,sizeof(FQ_ELEM)*K); // First K elements 
                                                
        #ifdef SPECK_FULL_G
            row_mat_mult(codewords[i]+K,u,PK->G_0_rref,K,K); // Last K elements
        #else
            row_mat_mult(codewords[i]+K,u,G0_rref.values,K,K); // Last K elements
        #endif
                                                
        histogram(x,codewords[i],N);

        LESS_SHA3_INC_INIT(&state_cmt_i);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, x, sizeof(FQ_ELEM)*Q);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, sig->salt, HASH_DIGEST_LENGTH);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint16_t));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)m, mlen);
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);

        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
    }

    LESS_SHA3_INC_FINALIZE(sig->digest, &state_cmt);

    // (b_0, ..., b_{t-1})
    uint8_t fixed_weight_string[T] = {0};
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++) {
        indices_to_publish[i] = !!(fixed_weight_string[i]);
    }

    int emitted_perms = 0;
    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    const uint32_t num_seeds_published =
            GGMPath(seed_tree,
                           indices_to_publish,
                           (unsigned char *) &sig->seed_storage);
    #ifdef SPECK_COMPRESS_C1S
        FQ_ELEM c1s[W][K];
    #endif

    for (uint32_t i = 0; i < T; i++) {
        if (fixed_weight_string[i] != 0) {
            const int perm_num = fixed_weight_string[i];

            for(uint8_t j = 0; j<K; j++){
                // Check undefined behaviour on iteration j=15
                #ifdef SPECK_COMPRESS_C1S
                    c1s[emitted_perms][j] = codewords[i][SK->permutations[perm_num-1][j]];
                #else
                    sig->c1s[emitted_perms][j] = codewords[i][SK->permutations[perm_num-1][j]];
                #endif
            }

            emitted_perms++;
        }
    }
    #ifdef SPECK_COMPRESS_C1S
        compress_c1s(sig->c1s,c1s);
    #endif
    return num_seeds_published;
} /* end SPECK_sign */

/// NOTE: non-constant time
/// \param PK[in]: public key
/// \param m[in]: message for which a signature was computed
/// \param mlen[in]: length of the message in bytes
/// \param sig[in]: signature
/// \return 0: on failure
///         1: on success
int SPECK_verify(const speck_pubkey_t *const PK,
                const char *const m,
                const uint64_t mlen,
                const speck_sign_t *const sig) {
    uint8_t fixed_weight_string[T] = {0};
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t published_seed_indexes[T];
    for (uint32_t i = 0; i < T; i++) {
        published_seed_indexes[i] = !!(fixed_weight_string[i]);
    }

    unsigned char seed_tree[NUM_NODES_SEED_TREE * SEED_LENGTH_BYTES] = {0};
    uint32_t rebuilding_seeds_went_fine;
    rebuilding_seeds_went_fine = RebuildGGM(seed_tree,
                                            published_seed_indexes,
                                            (unsigned char *) &sig->seed_storage,
                                            sig->salt);
    if (!rebuilding_seeds_went_fine) {
        return -1;
    }

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    int employed_perms = 0;

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);

    LESS_SHA3_INC_CTX state_cmt_i;
    uint8_t cmt_i[HASH_DIGEST_LENGTH];

    FQ_ELEM u[K];
    FQ_ELEM x[Q];
    FQ_ELEM c2[K];
    
    #ifdef SPECK_RESAMPLE_G
        rref_generator_mat_t G0_rref;
        generator_sample(&G0_rref, PK->G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        rref_generator_mat_t G0_rref;
        expand_to_rref_speck(&G0_rref,PK->G_0_rref);
    #endif


    #ifdef SPECK_COMPRESS_GP
        rref_generator_mat_t GP_rrefs[NUM_KEYPAIRS-1];
        for(int i=0; i<NUM_KEYPAIRS-1;i++){
            expand_to_rref_speck(&GP_rrefs[i],PK->SF_G[i]);
        }
    #endif

    #ifdef SPECK_COMPRESS_C1S
        FQ_ELEM c1s[W][K];
        expand_c1s(c1s,sig->c1s);
    #endif

    for (uint32_t i = 0; i < T; i++) {
        if (fixed_weight_string[i] == 0) {

            word_sample_salt(u,
                             linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                             sig->salt,
                             i);

            #ifdef SPECK_FULL_G
                row_mat_mult(c2,u,PK->G_0_rref,K,K);
            #else
                row_mat_mult(c2,u,G0_rref.values,K,K);
            #endif
            histogram_c1_c2(x,u,c2,K);
        } else {

            #ifdef SPECK_COMPRESS_C1S
                #ifdef SPECK_COMPRESS_GP
                    row_mat_mult(c2, c1s[employed_perms], GP_rrefs[fixed_weight_string[i]-1].values, K, K);
                #else
                    row_mat_mult(c2, c1s[employed_perms], PK->SF_G[fixed_weight_string[i]-1], K, K);
                #endif
                    histogram_c1_c2(x,c1s[employed_perms],c2,K);
            #else
                #ifdef SPECK_COMPRESS_GP
                    row_mat_mult(c2, sig->c1s[employed_perms], GP_rrefs[fixed_weight_string[i]-1].values, K, K);
                #else
                    row_mat_mult(c2, sig->c1s[employed_perms], PK->SF_G[fixed_weight_string[i]-1], K, K);
                #endif
                    histogram_c1_c2(x,sig->c1s[employed_perms],c2,K);
            #endif
            employed_perms++;
        }

        LESS_SHA3_INC_INIT(&state_cmt_i);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, x, sizeof(FQ_ELEM)*Q);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, sig->salt, HASH_DIGEST_LENGTH);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint16_t));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)m, mlen);
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);

        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
    }

    uint8_t cmt[HASH_DIGEST_LENGTH];
    LESS_SHA3_INC_FINALIZE(cmt, &state_cmt);

    return (verify(cmt, sig->digest,HASH_DIGEST_LENGTH) == 0);
} /* end SPECK_verify */

