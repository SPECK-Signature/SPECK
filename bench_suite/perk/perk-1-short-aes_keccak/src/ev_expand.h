
/**
 * @file ev_expand.h
 * @brief Header file for ev_expand.c
 *
 * Expansion of the elementary vectors
 */

#ifndef EV_EXPAND_H
#define EV_EXPAND_H

#include "data_structures.h"
#include "gf_arithmetic.h"
#include "parameters.h"

void sig_perk_tensor_product_to_ev(sig_perk_share_z_t shares_row[PERK_PARAM_N],
                                   sig_perk_beta_prime_t voles_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]);

void check_elementary_vector(sig_perk_check_ev_t elt_vec_check[PERK_PARAM_C],
                             sig_perk_beta_prime_t beta_prime_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]);

#endif
