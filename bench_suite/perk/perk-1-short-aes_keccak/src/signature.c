/**
 * @file signature.c
 * @brief Implementation of sign function
 */

#include "signature.h"
#include "parameters.h"

#include <stdio.h>
#include <string.h>
#include "crypto_memset.h"
#include "data_structures.h"
#include "ggm_tree.h"
#include "parsing.h"
#include "prove_pkp.h"
#include "randombytes.h"
#include "symmetric.h"
#include "verbose.h"
#include "voles.h"

void sig_perk_gen_first_challenge(uint8_t ch1[5 * PERK_SECURITY_BYTES + 8], const digest_t mu, const cmt_t h_com,
                                  const perk_vole_data_t c[PERK_PARAM_TAU - 1], const salt_t salt) {
    sig_perk_prg_state_t state_H21 = {0};
    sig_perk_prg_init(&state_H21, salt, NULL);
    sig_perk_prg_update(&state_H21, mu, sizeof(digest_t));
    sig_perk_prg_update(&state_H21, h_com, sizeof(cmt_t));
    sig_perk_prg_update(&state_H21, (uint8_t *)c, PERK_VOLE_DATA_BYTES * (PERK_PARAM_TAU - 1));
    sig_perk_prg_final(&state_H21, H2_1);
    sig_perk_prg(&state_H21, ch1, 5 * PERK_SECURITY_BYTES + 8);
}

void sig_perk_gen_second_challenge(ch2_t ch2, const uint8_t chall1[5 * PERK_SECURITY_BYTES + 8],
                                   const uint8_t u_tilde[PERK_VOLE_HASH_BYTES],
                                   const uint8_t h_V[2 * PERK_SECURITY_BYTES], const uint16_t t[PERK_PARAM_N]) {
    sig_perk_hash_state_t state_H22 = {0};
    sig_perk_hash_init(&state_H22, NULL, NULL, NULL);
    sig_perk_hash_update(&state_H22, chall1, 5 * PERK_SECURITY_BYTES + 8);
    sig_perk_hash_update(&state_H22, u_tilde, PERK_VOLE_HASH_BYTES);
    sig_perk_hash_update(&state_H22, h_V, 2 * PERK_SECURITY_BYTES);
    sig_perk_hash_update(&state_H22, (uint8_t *)t, 2 * PERK_PARAM_N);
    sig_perk_hash_final(&state_H22, ch2, H2_2);
}

void sig_perk_gen_third_challenge(ch3_t ch3, const ch2_t ch2, const sig_perk_f_poly_t *a, const uint64_t *ctr) {
    sig_perk_prg_state_t state_H23 = {0};
    sig_perk_prg_init(&state_H23, ch2, NULL);
    sig_perk_prg_update(&state_H23, (uint8_t *)a, sizeof(sig_perk_f_poly_t));
    sig_perk_prg_update(&state_H23, (uint8_t *)ctr, sizeof(uint64_t));
    sig_perk_prg_final(&state_H23, H2_3);
    sig_perk_prg(&state_H23, ch3, sizeof(ch3_t));

    // set to zero the last unused bits
    uint8_t mask = (uint8_t)((1U << ((PERK_CHALL_3_BITS % 8U))) - 1U);
    if (mask) {
        ch3[PERK_CHALL_3_BYTES - 1] &= mask;
    }
}

void sig_perk_compute_h_V(uint8_t h_V[2 * PERK_SECURITY_BYTES], uint8_t v_tilde[PERK_PARAM_RHO][PERK_VOLE_HASH_BYTES]) {
    sig_perk_hash_state_t state_H1 = {0};
    sig_perk_hash_init(&state_H1, NULL, NULL, NULL);

    for (unsigned i = 0; i < PERK_PARAM_RHO; ++i) {
        sig_perk_hash_update(&state_H1, v_tilde[i], PERK_VOLE_HASH_BYTES);
    }

    sig_perk_hash_final(&state_H1, h_V, H1);
}

int sig_perk_sign(sig_perk_signature_t *signature, const digest_t mu, const sig_perk_private_key_t *sk,
                  const sig_perk_public_key_t *pk) {
    uint8_t rand[2 * PERK_SEED_BYTES] = {0};
    uint8_t ch1[5 * PERK_SECURITY_BYTES + 8] = {0};
    sig_perk_beta_prime_t beta_array[PERK_PARAM_N][PERK_PARAM_D][PERK_PARAM_BASIS - 1] = {0};
    sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N] = {0};
    sig_perk_check_t col_check_array[PERK_PARAM_N] = {0};
    cmt_t h_com = {0};
    perk_vole_data_t u = {0};
    perk_vole_data_t v[PERK_PARAM_RHO] = {0};
    ggm_tree_t big_tree = {0};
    cmt_array_t cmt_array = {0};
    uint8_t v_tilde[PERK_PARAM_RHO][PERK_VOLE_HASH_BYTES] = {0};
    ch2_t ch2 = {0};
    i_vect_t i_vect = {0};
    uint8_t h_V[2 * PERK_SECURITY_BYTES] = {0};

    // Sample rand
    randombytes(rand, 2 * PERK_SEED_BYTES);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("rand", rand, 2 * PERK_SEED_BYTES);

    // Compute mseed and salt
    sig_perk_prg_state_t state_H3 = {0};
    sig_perk_prg_init(&state_H3, NULL, NULL);
    sig_perk_prg_update(&state_H3, sk->perm_seed, PERK_SEED_BYTES);
    sig_perk_prg_update(&state_H3, mu, PERK_HASH_BYTES);
    sig_perk_prg_update(&state_H3, rand, 2 * PERK_SEED_BYTES);
    sig_perk_prg_final(&state_H3, H3);
    sig_perk_prg(&state_H3, big_tree[0], PERK_SEED_BYTES);
    sig_perk_prg(&state_H3, signature->salt, sizeof(signature->salt));

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("tree root seed", big_tree[0], PERK_SEED_BYTES);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("salt", signature->salt, sizeof(signature->salt));

    // VOLE construction and commitments
    expand_ggm_tree(big_tree, signature->salt);
    build_ggm_tree_leaf_cmt(cmt_array, signature->salt, (const_ggm_tree_t)big_tree);
    sig_perk_vole_commit(h_com, signature->c, u, v, signature->salt, (const_ggm_tree_t)big_tree,
                         (const_cmt_array_t)cmt_array);

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("h_com", h_com, sizeof(cmt_t));

    // Compute challenge 1
    sig_perk_gen_first_challenge(ch1, mu, h_com, (const uint8_t(*)[sizeof(perk_vole_data_t)])signature->c,
                                 signature->salt);

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("ch1", ch1, sizeof(ch1));

    // VOLE consistency check
    sig_perk_vole_hash(signature->u_tilde, ch1, u);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("u_tilde", signature->u_tilde, sizeof(signature->u_tilde));
    for (uint16_t i = 0; i < PERK_PARAM_RHO; i++) {
        sig_perk_vole_hash(v_tilde[i], ch1, v[i]);
    }
    sig_perk_compute_h_V(h_V, v_tilde);

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("h_V", h_V, sizeof(h_V));

    // Committing to witness and PKP proof
    sig_perk_vole_permutation(signature->t, beta_array, z_array, col_check_array, sk, u, (const_vole_data_p_t)v);
    SIG_PERK_VERBOSE_PRINT_uint16_t_array("t", signature->t, PERK_PARAM_N);

    // Compute challenge 2
    sig_perk_gen_second_challenge(ch2, ch1, signature->u_tilde, h_V, signature->t);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("ch2", ch2, sizeof(ch2));
    sig_perk_check_pkp(&signature->a, col_check_array, beta_array, z_array, (const sig_perk_public_key_t *)pk, u,
                       (const_vole_data_p_t)v, ch2);
    SIG_PERK_VERBOSE_PRINT_f_poly_t_struct(&signature->a);

    int ret = open_vector_commitments(signature->ch3, &signature->ctr, signature->pdecom, i_vect,
                                      (const_ggm_tree_t)big_tree, ch2, &signature->a);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("ch3", signature->ch3, sizeof(signature->ch3));
    SIG_PERK_VERBOSE_PRINT_counter(signature->ctr);
    SIG_PERK_VERBOSE_PRINT_pdecom_seeds((const node_seed_t *)signature->pdecom);
    SIG_PERK_VERBOSE_PRINT_i_vect_t(i_vect);

    if (ret != PERK_SUCCESS) {
        return ret;
    }
    // copy commitments of the hidden leaves in the signature
    for (unsigned i = 0; i < PERK_PARAM_TAU; i++) {
        memcpy(signature->com_e_i[i], cmt_array[i_vect[i] - LEAVES_SEEDS_OFFSET], sizeof(cmt_t));
    }

    SIG_PERK_VERBOSE_PRINT_com_e_i((const cmt_t *)signature->com_e_i);

    return PERK_SUCCESS;
}
