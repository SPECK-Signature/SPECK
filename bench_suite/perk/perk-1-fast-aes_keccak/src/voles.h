/**
 * @file voles.h
 * @brief Header file for voles.c
 */

#ifndef SIG_PERK_VOLES_H
#define SIG_PERK_VOLES_H

#include <stdint.h>
#include "data_structures.h"
#include "gf_arithmetic.h"
#include "gf_poly_arithmetic.h"
#include "ggm_tree.h"
#include "parameters.h"

#define xkcp4x 1
#define xkcp1x 2

/**
 * @brief xor two perk_vole_data_t elements
 *
 * @param[out] out in0 xor in1
 * @param[in]  in0 input element
 * @param[in]  in1 input element
 */
static inline void xor_vole(perk_vole_data_t out, perk_vole_data_t in0, const perk_vole_data_t in1) {
    //
    for (unsigned i = 0; i < sizeof(perk_vole_data_t); i++) {
        out[i] = in0[i] ^ in1[i];
    }
}

/**
 * @brief implement ConvertToVOLE
 *
 * @param u[out]       perk_vole_data_t buffer filled with the computed u
 * @param v[out]       array of at least mu elements
 *                     filled with the computed v
 * @param subtree[in]  subtree for which compute the voles
 * @param salt[in]     salt for the PRG
 * @param ggm_tree[in] an expanded ggm_tree
 *
 * @return unsigned elements in the out voles array
 */
unsigned sig_perk_convert_to_vole(perk_vole_data_t u, perk_vole_data_t v[], const unsigned subtree, const salt_t salt,
                                  ggm_tree_t const ggm_tree);

/**
 * @brief permutes the seeds, zeroise r_0_0 and convert to voles
 *        implement Alg. 3.18 lines 2 and 3
 *
 * @param v[out]       array of at least mu elements
 *
 * @param subtree[in]  subtree for which compute the voles
 * @param delta_e[in]  delta
 * @param salt[in]     salt for the PRG
 * @param ggm_tree[in] an expanded ggm_tree
 *
 * @return unsigned elements in the out voles array
 */
unsigned sig_perk_permute_and_convert_to_vole(perk_vole_data_t v[], const unsigned subtree, uint32_t delta_e,
                                              const salt_t salt, const ggm_tree_t ggm_tree);

/**
 * @brief
 *
 * @param h_com[out]    Com2(com_0|| . . . ||com_τ−1) hash of the commitments of each subtree
 * @param c[out]
 * @param u[out]
 * @param v[out]
 * @param salt[in]      salt
 * @param ggm_tree[in]  an expanded ggm_tree
 * @param cmt_array[in] array of the leaf commitments of all subtree
 */
void sig_perk_vole_commit(cmt_t h_com, perk_vole_data_t c[PERK_PARAM_TAU - 1], perk_vole_data_t u,
                          perk_vole_data_t v[PERK_PARAM_RHO], const salt_t salt, ggm_tree_t const ggm_tree,
                          const cmt_array_t cmt_array);

/**
 * @brief impelmentation of VoleHash
 *
 * @param h[out] output hash
 * @param sd[in] input seed
 * @param x[in] input vector
 */
void sig_perk_vole_hash(uint8_t* h, uint8_t* sd, uint8_t* x);

static inline uint8_t sig_perk_get_vole_data_bit(const uint8_t* in, unsigned int index) {
    return (in[index / 8] >> (index % 8)) & 1;
}

static inline void sig_perk_v_to_tower_field(gf2_q_poly v_idx, unsigned idx, const perk_vole_data_t v[PERK_PARAM_RHO]) {
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        v_idx[i] = 0;
        for (unsigned j = 0; j < PERK_PARAM_Q; j++) {
            uint8_t bit = sig_perk_get_vole_data_bit(v[(i * PERK_PARAM_Q) + j], idx);
            v_idx[i] |= (uint16_t)bit << j;
        }
    }
}

static inline void sig_perk_check_zero_v_to_tower_field(gf2_q_poly out, unsigned idx,
                                                        const perk_vole_data_t v[PERK_PARAM_RHO]) {
    gf2_q_poly v_e_i[PERK_TOWER_FIELD_EXT] = {0};
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        unsigned idx1 = i * PERK_PARAM_Q + idx;

        gf2_q_poly v_i[PERK_PARAM_Q] = {0};
        for (unsigned j = 0; j < PERK_PARAM_Q; j++) {
            sig_perk_v_to_tower_field(v_i[j], idx1 + j, v);
        }

        for (unsigned e = 0; e < PERK_TOWER_FIELD_EXT; e++) {
            uint32_t ur_v_element = 0;
            for (unsigned j = 0; j < PERK_PARAM_Q; j++) {
                ur_v_element ^= ((uint32_t)v_i[j][e]) << j;
            }
            v_e_i[i][e] = sig_perk_gf2_q_reduce(ur_v_element);
        }
    }

    gf2_q_poly_ur vi_ur = {0};
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        for (unsigned j = 0; j < PERK_TOWER_FIELD_EXT; ++j) {
            vi_ur[i + j] ^= v_e_i[i][j];
        }
    }

    // Step 2 - Modular reduction modulo GF2_Q_POLY_MODULUS
    const gf2_q_elt modulus[] = GF2_Q_POLY_MODULUS;
    const size_t modulus_nb_coefs = sizeof(modulus) / sizeof(modulus[0]);
    int16_t max_deg = 2 * PERK_TOWER_FIELD_EXT - 1;
    for (int16_t i = max_deg - PERK_TOWER_FIELD_EXT; i > 0; --i) {
        for (size_t j = 0; j < modulus_nb_coefs - 1; ++j) {
            sig_perk_gf2_q_add(&vi_ur[i + modulus[j] - 1], vi_ur[i + modulus[j] - 1],
                               vi_ur[i + (PERK_TOWER_FIELD_EXT - 1)]);
        }
        vi_ur[i + (PERK_TOWER_FIELD_EXT - 1)] = 0;
    }
    memcpy(out, vi_ur, sizeof(gf2_q_elt) * PERK_TOWER_FIELD_EXT);
}

static inline void sig_perk_u_to_tower_field(gf2_q_poly u_idx, unsigned idx, const perk_vole_data_t u) {
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        u_idx[i] = 0;
        for (unsigned j = 0; j < PERK_PARAM_Q; j++) {
            uint16_t bit = sig_perk_get_vole_data_bit(u, idx);
            u_idx[i] |= bit << j;
            idx++;
        }
    }
}

int vole_reconstuct(cmt_t h_com, perk_vole_data_t q_prime[PERK_PARAM_RHO], i_vect_t i_vect,
                    const node_seed_t pdecom[PERK_PARAM_T_OPEN], const cmt_t com_e_i[PERK_PARAM_TAU],
                    const salt_t salt);

static inline void copy_vole(perk_vole_data_t out, perk_vole_data_t in0) {
    //
    for (unsigned i = 0; i < sizeof(perk_vole_data_t); i++) {
        out[i] = in0[i];
    }
}

#endif  // SIG_PERK_VOLES_H
