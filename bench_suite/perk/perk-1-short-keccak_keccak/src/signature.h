
/**
 * @file signature.h
 * @brief Header file for signature.c
 */

#ifndef SIG_PERK_SIGNATURE_H
#define SIG_PERK_SIGNATURE_H

#include <stdint.h>
#include "data_structures.h"

void sig_perk_gen_first_challenge(uint8_t ch1[5 * PERK_SECURITY_BYTES + 8], const digest_t mu, const cmt_t h_com,
                                  const perk_vole_data_t c[PERK_PARAM_TAU - 1], const salt_t salt);
void sig_perk_gen_second_challenge(ch2_t ch2, const uint8_t chall1[5 * PERK_SECURITY_BYTES + 8],
                                   const uint8_t u_tilde[PERK_VOLE_HASH_BYTES],
                                   const uint8_t h_V[2 * PERK_SECURITY_BYTES], const uint16_t t[PERK_PARAM_N]);

void sig_perk_gen_third_challenge(ch3_t ch3, const ch2_t ch2, const sig_perk_f_poly_t *a, const uint64_t *ctr);

void sig_perk_compute_h_V(uint8_t h_V[2 * PERK_SECURITY_BYTES], uint8_t v_tilde[PERK_PARAM_RHO][PERK_VOLE_HASH_BYTES]);
/**
 * @brief Generate a signature
 *
 * @param[out] signature a pointer to signature structure
 * @param[in]  mu  message digest µ := H1(pk||msg)
 * @param[in]  sk a pointer to secret key structure
 * @param[in]  pk a pointer to private key structure
 *
 * @return int returns PERK_SUCCESS on success, PERK_FAILURE otherwise
 */
int sig_perk_sign(sig_perk_signature_t *signature, const digest_t mu, const sig_perk_private_key_t *sk,
                  const sig_perk_public_key_t *pk);

#endif  // SIG_PERK_SIGNATURE_H
