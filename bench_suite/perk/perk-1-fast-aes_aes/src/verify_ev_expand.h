
/**
 * @file ev_expand.h
 * @brief Header file for ev_expand.c
 *
 * Expansion of the elementary vectors
 */

#ifndef VERIFY_EV_EXPAND_H
#define VERIFY_EV_EXPAND_H

#include "data_structures.h"
#include "gf_arithmetic.h"
#include "parameters.h"

void sig_perk_v_tensor_product_to_ev(gf2_q_poly shares_row[PERK_PARAM_N],
                                     gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6]);
void v_check_elementary_vector(gf2_q_poly q_prime_e_prime[PERK_PARAM_C], const gf2_q_poly delta,
                               const gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6]);
#endif
