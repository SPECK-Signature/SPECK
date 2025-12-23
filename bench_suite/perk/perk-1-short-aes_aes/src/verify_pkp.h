
#ifndef SIG_PERK_VERIFY_PKP_H
#define SIG_PERK_VERIFY_PKP_H

#include <stdint.h>
#include "data_structures.h"
#include "parameters.h"
#include "prove_pkp.h"

void sig_perk_expand_witness(uint8_t t_prime[2 * PERK_PARAM_L_ROW - 6], const uint16_t t);

void sig_perk_embed_masked_witness(gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6], const gf2_q_poly delta,
                                   const uint8_t t_prime[2 * PERK_PARAM_L_ROW - 6],
                                   const gf2_q_poly q[PERK_PARAM_L_ROW]);

void sig_perk_verify_compute_p_columns_check(gf2_q_poly col_check[PERK_PARAM_N],
                                             gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N], const gf2_q_poly delta);

void sig_perk_verify_compute_x_prime(gf2_q_poly q_x_prime[PERK_PARAM_N], gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N],
                                     const sig_perk_public_key_t *pk);

void sig_perk_verify_compute_y(gf2_q_poly q_y[PERK_PARAM_M], gf2_q_poly q_x_prime[PERK_PARAM_N],
                               const sig_perk_public_key_t *pk);

void sig_perk_verify_vole_ev(gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6], gf2_q_poly q_z[PERK_PARAM_N],
                             const gf2_q_poly delta, const uint16_t t, const gf2_q_poly q[PERK_PARAM_L_ROW]);

void sig_perk_verify_vole_permutation(gf2_q_poly q_beta[PERK_PARAM_N][2 * PERK_PARAM_L_ROW - 6],
                                      gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N], gf2_q_poly q_col_check[PERK_PARAM_N],
                                      const gf2_q_poly delta, const uint16_t t[PERK_PARAM_N],
                                      const perk_vole_data_t q[PERK_PARAM_RHO]);

uint8_t sig_perk_verify_check_pkp(const sig_perk_f_poly_t *a, const perk_vole_data_t q[], const gf2_q_poly delta,
                                  const uint16_t t[PERK_PARAM_N], const sig_perk_public_key_t *pk, const ch2_t ch2_bar);

uint8_t sig_perk_verify_check_zero(const gf2_q_poly delta, gf2_q_poly q_f, const sig_perk_f_poly_t *a,
                                   const perk_vole_data_t q[]);

#endif  // PERK_VERIFY_PKP_H
