
/**
 * @file keygen.h
 * @brief Header file for keygen.c
 */

#ifndef SIG_PERK_KEYGEN_H
#define SIG_PERK_KEYGEN_H

#include "data_structures.h"
#include "symmetric.h"

/**
 * @brief Generate a key pair
 *
 * @param [out] pk a pointer to public key structure
 * @param [out] sk a pointer to private key structure
 * @return int 0 if the key generation is successful
 */
uint8_t sig_perk_generate_keypair(sig_perk_public_key_t *pk, sig_perk_private_key_t *sk);

/**
 * @brief Sample a random matrix PERK_PARAM_M x PERK_PARAM_N over GF2_Q directly in RREF
 *
 * @param matrix [out] a pointer to a matrix structure
 * @param seed [in] a pointer to a seed structure, used to initialize the PRNG
 */
void sig_perk_mat_set_random_rref(sig_perk_mat_t matrix, const seed_t seed);

/**
 * @brief Compute a list of generators of the right-kernel of an input matrix in Row-Echelon Reduced Form
 *
 * @param [out] null_basis a pointer to a list of vectors, will be a list of generators of the right-kernel of the input
 * matix
 * @param [in] rref_matrix a pointer to a matrix structure already reduced in RREF
 * @return int 0 if the reduction is successful, 1 if the matrix is not full-rank
 */
void sig_perk_right_kernel(sig_perk_vec_t null_basis[PERK_PARAM_N - PERK_PARAM_M], sig_perk_mat_t rref_matrix);

/**
 * @brief Compute a list of generators of the right-kernel of an input matrix in Row-Echelon Reduced Form
 *
 * @param [out] kernel_vec a pointer to a vector in the kernel of mat_H
 * @param [in] mat_H a pointer to a matrix structure already reduced in RREF
 * @param seed [in] a pointer to a seed structure, used to initialize the PRNG
 * @return int 0 if the reduction is successful, 1 if the matrix is not full-rank
 */
void sig_perk_sample_kernel_element(sig_perk_vec_t kernel_vec, sig_perk_mat_t mat_H, seed_t seed);

uint16_t read_11bit_in_64bytearray(uint64_t *buffer, uint16_t pos, uint16_t index);

#endif  // SIG_PERK_KEYGEN_H
