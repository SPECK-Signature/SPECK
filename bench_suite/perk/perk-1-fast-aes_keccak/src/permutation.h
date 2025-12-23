
/**
 * @file permutation.h
 * @brief header file for permutation.c
 */

#ifndef SIG_PERK_PERMUTATION_H
#define SIG_PERK_PERMUTATION_H

#include <stdint.h>
#include "data_structures.h"

/**
 * @brief Set permutation to zero
 *
 * @param [out,in] input_perm a permutation
 */
void sig_perk_perm_set_zero(perm_t input_perm);

/**
 * @brief Generate a random permutation form a seed
 *
 * @param [out] p a permutation
 * @param [in] seed a string containing a seed
 */
void sig_perk_perm_set_random(perm_t p, const uint8_t seed[PERK_SEED_BYTES]);

/**
 * @brief Generate a random permutation form random values
 *
 * @param [out] p a permutation
 * @param [in] rnd_buff an array containing random values
 */
int sig_perk_perm_gen_given_random_input(perm_t p, const uint16_t rnd_buff[PERK_PARAM_N]);

/**
 * @brief Compute the inverse of a permutation
 *
 * o = p1^(-1)
 *
 * @param [out] o a permutation
 * @param [in] p a permutation
 */
void sig_perk_perm_inverse(perm_t o, const perm_t p);

/**
 * @brief Apply a permutation on a vector
 *
 * @param [out] output a permuted vector
 * @param [in] p a permutation
 * @param [in] input a vector
 */
void sig_perk_perm_vect_permute(sig_perk_vec_t output, const perm_t p, const sig_perk_vec_t input);

#endif
