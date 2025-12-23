
/**
 * @file verify.h
 * @brief Header file for verify.c
 */

#ifndef SIG_PERK_VERIFY_H
#define SIG_PERK_VERIFY_H

#include "data_structures.h"
#include "signature.h"

/**
 * @brief Verify a signature
 *
 * @param[in] signature a pointer to signature structure
 * @param[in] mu message digest µ := H1(pk||msg)
 * @param[in] pk a pointer to private key structure
 *
 * @return[in] int returns PERK_SUCCESS if the signature verify, PERK_FAILURE otherwise
 */
int sig_perk_verify(const sig_perk_signature_t *signature, const digest_t mu, const sig_perk_public_key_t *pk);

#endif  // SIG_PERK_VERIFY_H
