
/**
 * @file symmetric_times4.h
 * @brief Header file for symmetric_times4.c
 */

#ifndef SIG_PERK_SYMMETRIC_TIMES4_H
#define SIG_PERK_SYMMETRIC_TIMES4_H

#include <stdint.h>
#include "KeccakHashtimes4.h"
#include "parameters.h"
#include "symmetric.h"

#if (PERK_SECURITY_BYTES == 16)
#define Keccak_HashInitializetimes4_SHAKE Keccak_HashInitializetimes4_SHAKE128  // SHAKE128
#define Keccak_HashInitializetimes4_SHA3  Keccak_HashInitializetimes4_SHA3_256
#elif (PERK_SECURITY_BYTES == 24)
#define Keccak_HashInitializetimes4_SHAKE Keccak_HashInitializetimes4_SHAKE256  // SHAKE256
#define Keccak_HashInitializetimes4_SHA3  Keccak_HashInitializetimes4_SHA3_384
#elif (PERK_SECURITY_BYTES == 32)
#define Keccak_HashInitializetimes4_SHAKE Keccak_HashInitializetimes4_SHAKE256  // SHAKE256
#define Keccak_HashInitializetimes4_SHA3  Keccak_HashInitializetimes4_SHA3_512
#endif

#define Keccak_HashUpdatetimes4_SHAKE(state, input, inlen)    Keccak_HashUpdatetimes4(state, input, (inlen) * 8)
#define Keccak_HashFinaltimes4_SHAKE(state)                   Keccak_HashFinaltimes4(state, NULL)
#define Keccak_HashSqueezetimes4_SHAKE(state, output, outlen) Keccak_HashSqueezetimes4(state, output, (outlen) * 8)
#define Keccak_HashUpdatetimes4_SHA3(state, input, inlen)     Keccak_HashUpdatetimes4(state, input, (inlen) * 8)
#define Keccak_HashFinaltimes4_SHA3(state, digest)            Keccak_HashFinaltimes4(state, digest)

typedef Keccak_HashInstancetimes4 sig_perk_prg_times4_state_t;
typedef Keccak_HashInstancetimes4 sig_perk_hash_times4_state_t;

/**
 * @brief Initialize a PRNG times4
 *        absorb the salt if not NULL and the seeds
 *
 * A variant that uses 4 parallel instances
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] salt a string containing the salt. If Null no salt is absorbed.
 * @param [in] seed4 an array of 4 string containing the seeds. If Null no seed is absorbed.
 */
void sig_perk_prg_times4_init(sig_perk_prg_times4_state_t *state, const salt_t salt, const uint8_t *seed4[4]);

/**
 * @brief absorb additional data
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] data4 an array of 4 pointers to the data to be absorbed.
 * @param [in] data_size size of the data buffers.
 */
void sig_perk_prg_times4_update(sig_perk_prg_times4_state_t *state, const uint8_t *data4[4], const size_t data_size);

/**
 * @brief finalize the PRG absorbing the domain separator
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] domain a byte that is the domain separator.
 */
void sig_perk_prg_times4_final(sig_perk_prg_times4_state_t *state, const uint8_t domain);

/**
 * @brief PRNG times4
 *
 * A variant that uses 4 parallel instances
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [out] output4 an array of 4 pointers to the buffer to be filled
 * @param [in] outlen size of the output
 */
void sig_perk_prg_times4(sig_perk_prg_times4_state_t *state, uint8_t *output4[4], size_t outlen);

/**
 * @brief initialize the HASH times4 function
 *        absorb the salt and ctr if != NULL
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [in] salt a string containing the salt. If NULL salt is not absorbed.
 * @param [in] tau4 an array of 4 uint8_t absorbed after the salt. If NULL tau is not absorbed.
 * @param [in] n4 an array of 4 uint16_t absorbed after the salt. If NULL n is not absorbed.
 */
void sig_perk_hash_times4_init(sig_perk_hash_times4_state_t *state, const salt_t salt, const uint8_t tau4[4],
                               const uint16_t n4[4]);

/**
 * @brief HASH update times4
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [in] message4 an array of 4 pointers to the message to be absorbed.
 * @param [in] message_size size of the messages.
 */
void sig_perk_hash_times4_update(sig_perk_hash_times4_state_t *state, const uint8_t *message4[4],
                                 const size_t message_size);

/**
 * @brief output the 4 digests for the chosen hash function (domain)
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [out] digest4 an array of 4 pointers to the output digests.
 * @param [in] domain a byte that is the domain separator.
 */
void sig_perk_hash_times4_final(sig_perk_hash_times4_state_t *state, uint8_t *digest4[4], const uint8_t domain);

#endif
