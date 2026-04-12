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
        sample_generator(&G0_rref, PK->G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        sample_generator(&G0_rref, G_0_seed);
        compress_rref_speck_non_IS(PK->G_0_rref,&G0_rref);
    #endif
    #ifdef SPECK_FULL_G
        sample_generator(&G0_rref, G_0_seed);
        memcpy(PK->G_0_rref,G0_rref.values,sizeof(uint16_t)*K*N_K_pad);
    #endif
 
    generator_mat_t tmp_full_G;
    generator_rref_expand(&tmp_full_G, &G0_rref);

    // The first private key monomial is an ID matrix, no need for random generation, hence NUM_KEYPAIRS-1 
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
        generator_RREF_speck(&result_G, is_pivot_column);

        permutation_t private_rref_perm;
        generate_rref_perm(&private_rref_perm, is_pivot_column);

        for(POSITION_T j = 0; j<N; j++){
            SK->permutations[i][j] = private_perm.values[private_rref_perm.values[j]];
        }



        #ifdef SPECK_COMPRESS_GP
            compress_rref_speck(PK->SF_G[i],&result_G,is_pivot_column);
        #else
            for(int k=0; k<K; k++){
                memset(PK->SF_G[i][k],0,sizeof(FQ_ELEM)*(N_K_pad));
            }
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

    // generate seeds
    unsigned char seeds[T*SEED_LENGTH_BYTES];
    randombytes(seeds, T*SEED_LENGTH_BYTES);


    /*         Public G_0 expansion                  */
    #ifdef SPECK_RESAMPLE_G
        rref_generator_mat_t G0_rref;
        sample_generator(&G0_rref, G_0_seed);
    #endif
    #ifdef SPECK_COMPRESS_G
        rref_generator_mat_t G0_rref;
        expand_to_rref_speck(&G0_rref,PK->G_0_rref);
    #endif

    FQ_ELEM ordering[N_pad] = {0};
    FQ_ELEM mset[Q] = {0};
    FQ_ELEM u[K_pad] = {0};
    FQ_ELEM c2[N_K_pad] = {0};
    FQ_ELEM codewords[T][N_pad] = {0};
    FQ_ELEM pool[Q] = {0};

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);

    LESS_SHA3_INC_CTX state_cmt_i;
    uint8_t cmt_i[HASH_DIGEST_LENGTH];
    LESS_SHA3_INC_CTX state_cmt_base;
    LESS_SHA3_INC_INIT(&state_cmt_base);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, sig->salt, HASH_DIGEST_LENGTH);

    SHAKE_STATE_STRUCT shake_monomial_state = {0};


    uint8_t c_repetition_flag = 1;
    uint8_t u_repetition_flag = 1;
    uint8_t idx;
    uint16_t s;
 
    for (uint32_t i = 0; i < T; i++) {

        //memset(&shake_monomial_state, 0, sizeof(SHAKE_STATE_STRUCT));


        word_sample_salt(&shake_monomial_state,
                         seeds + i * SEED_LENGTH_BYTES,
                         sig->salt,
                         i);

        for (uint32_t j = 0; j < Q; j++){
            pool[j] = j;
        }
        sample_u_fisher_yates(&shake_monomial_state,u,pool);

        row_mat_mult(c2,u,
                K,N_K_pad,
            #ifdef SPECK_FULL_G
                PK->G_0_rref,
            #else
                G0_rref.values,
            #endif
                K,N-K); // Last K elements
                        //

        c_repetition_flag = histogram_c1_c2_counting(mset,u,c2,K,N-K);
    
        while(c_repetition_flag!=0){
            rand_range_K_state_elements(&shake_monomial_state,&idx,1);
            fq_star_rnd_state_elements(&shake_monomial_state,&s,1);

            u[idx] = u[idx]+s;
            u[idx] = u[idx] - 16381;
            u[idx] = ((-(u[idx]>>15))&16381) + u[idx];
            
            row_sum(c2,PK->G_0_rref[idx],s,N-K);

            c_repetition_flag = histogram_c1_c2_counting(mset,u,c2,K,N-K); //mset set to zero inside
        }

        //histogram_c1_c2(mset,u,c2,K,N-K);
        gen_ord_from_hist(ordering,mset);


        memcpy(codewords[i],(uint8_t *) u,sizeof(FQ_ELEM)*K);
        memcpy(codewords[i]+K,(uint8_t *) c2,sizeof(FQ_ELEM)*(N-K));

        memcpy(&state_cmt_i,&state_cmt_base,sizeof(state_cmt_base));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (uint8_t *)ordering, sizeof(uint16_t)*N);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint8_t));
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);

        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
    }

    LESS_SHA3_INC_FINALIZE(sig->digest, &state_cmt);

    uint8_t challenge_string[T];

    //SampleChallengeUniform(challenge_string, sig->digest);
    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state,(const unsigned char *) sig->digest,HASH_DIGEST_LENGTH);
    rand_range_chal_state_elements(&shake_state, challenge_string,T);

    int chal_0_ctr = 0;
    int chal_k_ctr = 0;

    #ifdef SPECK_COMPRESS_C1S

    for (int i=0; i<T; i++){
        if(challenge_string[i] != 0){
            chal_k_ctr ++;
        }
    }

    FQ_ELEM c1s[chal_k_ctr][K_pad];
    for(int i=0; i<chal_k_ctr; i++){
        memset(c1s[i],0,sizeof(uint16_t)*K_pad);
    }
    chal_k_ctr = 0;

    #endif


    for (uint32_t i = 0; i < T; i++) {
        if (challenge_string[i] != 0) {
            const int perm_num = challenge_string[i];

            for(uint8_t j = 0; j<K; j++){
                #ifdef SPECK_COMPRESS_C1S
                    c1s[chal_k_ctr][j] = codewords[i][SK->permutations[perm_num-1][j]];
                #else
                    sig->c1s[chal_k_ctr][j] = codewords[i][SK->permutations[perm_num-1][j]];
                #endif
            }

            chal_k_ctr+=1;
        }else{
            memcpy(sig->seed_storage[chal_0_ctr],seeds + i*SEED_LENGTH_BYTES,SEED_LENGTH_BYTES);
            chal_0_ctr+=1;
        }
    }
    #ifdef SPECK_COMPRESS_C1S
        compress_c1s(sig->c1s,chal_k_ctr,c1s);
    #endif

    //return num_seeds_published;
    return chal_0_ctr;
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
    uint8_t challenge_string[T] = {0};
    //SampleChallengeUniform(challenge_string, sig->digest);

    SHAKE_STATE_STRUCT shake_state;
    initialize_csprng(&shake_state,(const unsigned char *) sig->digest,HASH_DIGEST_LENGTH);
    rand_range_chal_state_elements(&shake_state, challenge_string,T);

    int chal_0_ctr = 0;
    int chal_k_ctr = 0;

    #ifdef SPECK_COMPRESS_C1S
    for (int i=0; i<T; i++){
        if(challenge_string[i] != 0){
            chal_k_ctr ++;
        }
    }

    FQ_ELEM c1s[chal_k_ctr][K_pad];
    for(int i=0; i<chal_k_ctr; i++){
        memset(c1s[i],0,sizeof(uint16_t)*K_pad);
    }

    expand_c1s(chal_k_ctr,c1s,sig->c1s);
    chal_k_ctr = 0;
    #endif

    LESS_SHA3_INC_CTX state_cmt;
    LESS_SHA3_INC_INIT(&state_cmt);

    LESS_SHA3_INC_CTX state_cmt_i;
    uint8_t cmt_i[HASH_DIGEST_LENGTH];

    FQ_ELEM u[K_pad] = {0};
    FQ_ELEM ordering[N] = {0};
    uint16_t mset[Q] = {0};
    FQ_ELEM c2[N_K_pad] = {0};
    
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



    LESS_SHA3_INC_CTX state_cmt_base;
    LESS_SHA3_INC_INIT(&state_cmt_base);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, (const uint8_t *)m, mlen);
    LESS_SHA3_INC_ABSORB(&state_cmt_base, sig->salt, HASH_DIGEST_LENGTH);

    SHAKE_STATE_STRUCT shake_monomial_state = {0};

    uint8_t idx;
    uint16_t s;
    uint8_t repetition_flag = 1;
    FQ_ELEM pool[Q];

    for (uint32_t i = 0; i < T; i++) {
        //memset(&shake_monomial_state, 0, sizeof(SHAKE_STATE_STRUCT));
        if (challenge_string[i] == 0) {

            word_sample_salt(&shake_monomial_state,
                             //linearized_rounds_seeds + i * SEED_LENGTH_BYTES,
                             sig->seed_storage[chal_0_ctr],
                             sig->salt,
                             i);

            //rand_range_q_state_elements(&shake_monomial_state,u,K);
            for (uint32_t j = 0; j < Q; j++){
                pool[j] = j;
            }
            sample_u_fisher_yates(&shake_monomial_state,u,pool);

            row_mat_mult(c2,u,
                    K,N_K_pad,
                #ifdef SPECK_FULL_G
                    PK->G_0_rref,
                #else
                    G0_rref.values,
                #endif
                    K,N-K); // Last K elements
                            
            repetition_flag = histogram_c1_c2_counting(mset,u,c2,K,N-K);

            while(repetition_flag!=0){
                rand_range_K_state_elements(&shake_monomial_state,&idx,1);
                fq_star_rnd_state_elements(&shake_monomial_state,&s,1);

                u[idx] = u[idx]+s;
                u[idx] = u[idx] - 16381;
                u[idx] = ((-(u[idx]>>15))&16381) + u[idx];

                row_sum(c2,PK->G_0_rref[idx],s,N-K);

                repetition_flag = histogram_c1_c2_counting(mset,u,c2,K,N-K); //mset set to zero inside
            }

            chal_0_ctr+=1;
        } else {

            row_mat_mult(c2,
                        #ifdef SPECK_COMPRESS_C1S
                            c1s[chal_k_ctr],
                        #else
                            sig->c1s[chal_k_ctr],
                        #endif
                            K,N_K_pad,
                        #ifdef SPECK_COMPRESS_GP
                            GP_rrefs[challenge_string[i]-1].values,
                        #else
                            PK->SF_G[challenge_string[i]-1],
                        #endif
                            K,N-K);
            histogram_c1_c2(
                    mset,
                    #ifdef SPECK_COMPRESS_C1S
                        c1s[chal_k_ctr],
                    #else
                        sig->c1s[chal_k_ctr],
                    #endif
                    c2,
                    K,N-K);

            chal_k_ctr++;
        }

        gen_ord_from_hist(ordering,mset);

        memcpy(&state_cmt_i,&state_cmt_base,sizeof(state_cmt_base));
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)ordering, sizeof(FQ_ELEM)*N);
        LESS_SHA3_INC_ABSORB(&state_cmt_i, (const uint8_t *)&i, sizeof(uint8_t));
        LESS_SHA3_INC_FINALIZE(cmt_i, &state_cmt_i);
        LESS_SHA3_INC_ABSORB(&state_cmt, cmt_i, HASH_DIGEST_LENGTH);
    }


    uint8_t cmt[HASH_DIGEST_LENGTH];
    LESS_SHA3_INC_FINALIZE(cmt, &state_cmt);

    return (verify(cmt, sig->digest,HASH_DIGEST_LENGTH) == 0);
} /* end SPECK_verify */

