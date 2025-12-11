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
#include "csprng_hash.h"

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
    //gen_seed_tree(seed_tree, ephem_permutations_seed, sig->salt);

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    // FINO A QUI È TUTTO UGUALE!

    /*         Public G_0 expansion                  */
    #ifdef SPECK_RESAMPLE_G
        rref_generator_mat_t G0_rref;
        generator_sample(&G0_rref, G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        rref_generator_mat_t G0_rref;
        expand_to_rref_speck(&G0_rref,PK->G_0_rref);
    #endif

    FQ_ELEM x[Q];
    FQ_ELEM codewords[T][N_pad];

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);
    /*
    LESS_SHA3_INC_CTX state_cmt_i;
    LESS_SHA3_INC_CTX state_cmt_base;
    LESS_SHA3_INC_INIT(&state_cmt_base);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, sig->salt, HASH_DIGEST_LENGTH);
    */

    uint8_t cmt_i_input_buffer[4][mlen + HASH_DIGEST_LENGTH + sizeof(FQ_ELEM)*Q];
    uint16_t cmt_i_dsc_buffer[4];
    uint8_t cmt_i_digest_buffer[4][HASH_DIGEST_LENGTH];
    uint8_t buffer_len = 0;

    for(int8_t i = 0; i < 4; i++){
        memcpy(cmt_i_input_buffer[i],m,mlen);
        memcpy(cmt_i_input_buffer[i] + mlen,sig->salt,HASH_DIGEST_LENGTH);
    }

    for (uint32_t i = 0; i < T; i++) {
        word_sample_salt(codewords[i],
                         linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                         sig->salt,
                         i);
                                                
        row_mat_mult(codewords[i]+K,codewords[i],
            #ifdef SPECK_FULL_G
                PK->G_0_rref,
            #else
                G0_rref.values,
            #endif
                K,K); // Last K elements
                                                
        histogram(x,codewords[i],N);

        memcpy(cmt_i_input_buffer[buffer_len] + mlen + HASH_DIGEST_LENGTH, x, sizeof(FQ_ELEM)*Q);   
        cmt_i_dsc_buffer[buffer_len] = HASH_DOMAIN_SEP_CONST + i;
        buffer_len += 1;

        if(buffer_len == 4 || i == T-1){
            hash_par(
                buffer_len,
                cmt_i_digest_buffer[0],
                cmt_i_digest_buffer[1],
                cmt_i_digest_buffer[2],
                cmt_i_digest_buffer[3],
                cmt_i_input_buffer[0],
                cmt_i_input_buffer[1],
                cmt_i_input_buffer[2],
                cmt_i_input_buffer[3],
                mlen + HASH_DIGEST_LENGTH + sizeof(FQ_ELEM)*Q,
                cmt_i_dsc_buffer[0],
                cmt_i_dsc_buffer[1],
                cmt_i_dsc_buffer[2],
                cmt_i_dsc_buffer[3]
            );

            for(int j = 0; j < buffer_len; j++){
                LESS_SHA3_INC_ABSORB(&state_cmt,cmt_i_digest_buffer[j],HASH_DIGEST_LENGTH);
            }

            buffer_len = 0;
        }

        /*
        memcpy(&state_cmt_i,&state_cmt_base,sizeof(state_cmt_base));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, x, sizeof(FQ_ELEM)*Q);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint16_t));
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);
        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
        */
    }

    LESS_SHA3_INC_FINALIZE(sig->digest, &state_cmt);

    // (b_0, ..., b_{t-1})
    uint8_t fixed_weight_string[T];
    SampleChallenge(fixed_weight_string, sig->digest);

    uint8_t indices_to_publish[T];
    for (uint32_t i = 0; i < T; i++) {
        indices_to_publish[i] = !!(fixed_weight_string[i]);
    }

    int emitted_perms = 0;
    memset(&sig->seed_storage, 0, SEED_TREE_MAX_PUBLISHED_BYTES);

    const uint32_t num_seeds_published = 
        GGMPath(seed_tree,indices_to_publish,(unsigned char *) &sig->seed_storage);
        //seed_path((unsigned char *) &sig->seed_storage, seed_tree, indices_to_publish);

    #ifdef SPECK_COMPRESS_C1S
        FQ_ELEM c1s[W][K_pad];
    #endif

    for (uint32_t i = 0; i < T; i++) {
        if (fixed_weight_string[i] != 0) {
            const int perm_num = fixed_weight_string[i];

            for(uint8_t j = 0; j<K; j++){
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
    rebuilding_seeds_went_fine = 
                RebuildGGM(seed_tree,published_seed_indexes,(unsigned char *) &sig->seed_storage,sig->salt);
                //rebuild_tree(seed_tree,published_seed_indexes,(unsigned char *) &sig->seed_storage,sig->salt);
    if (!rebuilding_seeds_went_fine) {
        return -1;
    }

    unsigned char linearized_rounds_seeds[T*SEED_LENGTH_BYTES] = {0};
    seed_leaves(linearized_rounds_seeds,seed_tree);

    int employed_perms = 0;

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);

    /*
    LESS_SHA3_INC_CTX state_cmt_i;
    uint8_t cmt_i[HASH_DIGEST_LENGTH];
    */

    FQ_ELEM u[K];
    FQ_ELEM x[Q];
    FQ_ELEM c2[K_pad];
    
    #ifndef SPECK_FULL_G
        rref_generator_mat_t G0_rref;
        #ifdef SPECK_RESAMPLE_G
            generator_sample(&G0_rref, PK->G_0_seed);
        #endif
        #ifdef SPECK_COMPRESS_G
            expand_to_rref_speck(&G0_rref,PK->G_0_rref);
        #endif
    #endif


    #ifdef SPECK_COMPRESS_GP
        rref_generator_mat_t GP_rrefs[NUM_KEYPAIRS-1];
        for(int i=0; i<NUM_KEYPAIRS-1;i++){
            expand_to_rref_speck(&GP_rrefs[i],PK->SF_G[i]);
        }
    #endif

    #ifdef SPECK_COMPRESS_C1S
        FQ_ELEM c1s[W][K_pad];
        expand_c1s(c1s,sig->c1s);
    #endif

    /*
    LESS_SHA3_INC_CTX state_cmt_base;
    LESS_SHA3_INC_INIT(&state_cmt_base);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, sig->salt, HASH_DIGEST_LENGTH);
    */

    uint8_t cmt_i_input_buffer[4][mlen + HASH_DIGEST_LENGTH + sizeof(FQ_ELEM)*Q];
    uint16_t cmt_i_dsc_buffer[4];
    uint8_t cmt_i_digest_buffer[4][HASH_DIGEST_LENGTH];
    uint8_t buffer_len = 0;

    for(int8_t i = 0; i < 4; i++){
        memcpy(cmt_i_input_buffer[i],m,mlen);
        memcpy(cmt_i_input_buffer[i] + mlen,sig->salt,HASH_DIGEST_LENGTH);
    }

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


            row_mat_mult(c2,
                        #ifdef SPECK_COMPRESS_C1S
                            c1s[employed_perms],
                        #else
                            sig->c1s[employed_perms],
                        #endif
                        #ifdef SPECK_COMPRESS_GP
                            GP_rrefs[fixed_weight_string[i]-1].values,
                        #else
                            PK->SF_G[fixed_weight_string[i]-1],
                        #endif
                            K,K);

            histogram_c1_c2(x,
                    #ifdef SPECK_COMPRESS_C1S
                        c1s[employed_perms],
                    #else
                        sig->c1s[employed_perms],
                    #endif
                    c2,K);

            employed_perms++;
        }


        memcpy(cmt_i_input_buffer[buffer_len] + mlen + HASH_DIGEST_LENGTH, x, sizeof(FQ_ELEM)*Q);   
        cmt_i_dsc_buffer[buffer_len] = HASH_DOMAIN_SEP_CONST + i;
        buffer_len += 1;

        if(buffer_len == 4 || i == T-1){
            hash_par(
                buffer_len,
                cmt_i_digest_buffer[0],
                cmt_i_digest_buffer[1],
                cmt_i_digest_buffer[2],
                cmt_i_digest_buffer[3],
                cmt_i_input_buffer[0],
                cmt_i_input_buffer[1],
                cmt_i_input_buffer[2],
                cmt_i_input_buffer[3],
                mlen + HASH_DIGEST_LENGTH + sizeof(FQ_ELEM)*Q,
                cmt_i_dsc_buffer[0],
                cmt_i_dsc_buffer[1],
                cmt_i_dsc_buffer[2],
                cmt_i_dsc_buffer[3]
            );

            for(int j = 0; j < buffer_len; j++){
                LESS_SHA3_INC_ABSORB(&state_cmt,cmt_i_digest_buffer[j],HASH_DIGEST_LENGTH);
            }

            buffer_len = 0;
        }

        /*
        memcpy(&state_cmt_i,&state_cmt_base,sizeof(state_cmt_base));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, x, sizeof(FQ_ELEM)*Q);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint16_t));
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);

        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
        */
    }

    uint8_t cmt[HASH_DIGEST_LENGTH];
    LESS_SHA3_INC_FINALIZE(cmt, &state_cmt);

    return (verify(cmt, sig->digest,HASH_DIGEST_LENGTH) == 0);
} /* end SPECK_verify */

