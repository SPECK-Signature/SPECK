
/**
 * @file data_structures.h
 * @brief common data structures for the scheme
 */

#ifndef SIG_PERK_DATA_STRUCTURES_H
#define SIG_PERK_DATA_STRUCTURES_H

#include <stdint.h>
#include "gf_arithmetic.h"
#include "gf_poly_arithmetic.h"
#include "ggm_tree.h"
#include "parameters.h"

/**
 * @brief Permutation perm_t
 *
 * This structure contains an array of integers that is a permutation
 */
typedef uint8_t perm_t[PERK_PARAM_N];

typedef uint16_t sig_perk_vec_t[PERK_PARAM_N];
typedef sig_perk_vec_t sig_perk_mat_t[PERK_PARAM_M];

/**
 * @brief
 *
 */
typedef uint8_t perk_vole_data_t[PERK_VOLE_DATA_BYTES];

/**
 * @brief pointer to const perk_vole_data_t
 */
typedef const uint8_t (*const const_vole_data_p_t)[PERK_VOLE_DATA_BYTES];

typedef uint8_t ch3_t[PERK_CHALL_3_BYTES];

typedef uint8_t ch2_t[2 * PERK_SECURITY_BYTES];

typedef struct {
    uint8_t H_seed[PERK_SEED_BYTES];
    sig_perk_mat_t H;
    sig_perk_vec_t x;
} sig_perk_public_key_t;

typedef struct {
    uint8_t perm_seed[PERK_SEED_BYTES];
    perm_t p;
} sig_perk_private_key_t;

typedef struct {
    uint8_t enc_pos_array[PERK_PARAM_D];
    uint8_t w_prime[PERK_PARAM_D];
    uint16_t w;
    uint16_t t;
} sig_perk_sk_encodings_t;

typedef uint8_t gf2_elt;

typedef struct {
    gf2_elt u;
    gf2_q_poly v;
} sig_perk_beta_prime_t;

typedef struct {
    gf2_elt u;
    gf2_q_poly v[PERK_PARAM_D];
} sig_perk_share_z_t;

typedef struct {
    gf2_q_elt u;
    gf2_q_poly v[PERK_PARAM_D];
} sig_perk_share_t;

typedef struct {
    gf2_elt u;
    gf2_q_poly v[PERK_PARAM_D];
} sig_perk_check_t;

typedef struct {
    gf2_q_poly u;
    gf2_q_poly v[PERK_PARAM_D];
} sig_perk_f_poly_t;

typedef struct {
    gf2_elt u;
    gf2_q_poly v[2];
} sig_perk_check_ev_t;

typedef struct {
    gf2_q_poly u;
    gf2_q_poly v[2];
} sig_perk_check_ev_by_alpha_t;

typedef struct {
    perk_vole_data_t c[PERK_PARAM_TAU - 1];
    uint8_t u_tilde[PERK_VOLE_HASH_BYTES];
    uint16_t t[PERK_PARAM_N];
    sig_perk_f_poly_t a;
    node_seed_t pdecom[PERK_PARAM_T_OPEN];
    cmt_t com_e_i[PERK_PARAM_TAU];
    ch3_t ch3;
    uint64_t ctr;
    salt_t salt;
} sig_perk_signature_t;

#endif  // SIG_PERK_DATA_STRUCTURES_H
