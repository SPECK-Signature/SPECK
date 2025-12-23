
/**
 * @file symmetric.h
 * @brief Header file for symmetric.c
 */

#ifndef SIG_PERK_SYMMETRIC_H
#define SIG_PERK_SYMMETRIC_H

#include <stdint.h>
#include "KeccakHash.h"
#include "parameters.h"

/**
 * @brief Salt salt_t
 *
 * This structure contains the salt
 */
typedef uint8_t salt_t[PERK_SALT_BYTES] __attribute__((aligned(16)));

/**
 * @brief Digest digest_t
 *
 * This structure contains the digest
 */
typedef uint8_t digest_t[PERK_HASH_BYTES];

/**
 * @brief Seed seed_t
 *
 * This structure defines a string containing PERK_SEED_BYTES bytes
 */
typedef uint8_t seed_t[PERK_SEED_BYTES];

#if (PERK_SECURITY_BYTES == 16)
#define PRNG_BLOCK_SIZE 168  // SHAKE128 Block Size
#elif (PERK_SECURITY_BYTES == 24)
#define PRNG_BLOCK_SIZE 136  // SHAKE256 Block Size
#elif (PERK_SECURITY_BYTES == 32)
#define PRNG_BLOCK_SIZE 136  // SHAKE256 Block Size
#endif

#if (PERK_SECURITY_BYTES == 16)
#define Keccak_HashInitialize_SHAKE(state) Keccak_HashInitialize_SHAKE128(state)
#define Keccak_HashInitialize_SHA3(state)  Keccak_HashInitialize_SHA3_256(state)
#elif (PERK_SECURITY_BYTES == 24)
#define Keccak_HashInitialize_SHAKE(state) Keccak_HashInitialize_SHAKE256(state)
#define Keccak_HashInitialize_SHA3(state)  Keccak_HashInitialize_SHA3_384(state)
#elif (PERK_SECURITY_BYTES == 32)
#define Keccak_HashInitialize_SHAKE(state) Keccak_HashInitialize_SHAKE256(state)
#define Keccak_HashInitialize_SHA3(state)  Keccak_HashInitialize_SHA3_512(state)
#endif

#define Keccak_HashUpdate_SHAKE(state, input, inlen)    Keccak_HashUpdate(state, input, (inlen) * 8)
#define Keccak_HashFinal_SHAKE(state)                   Keccak_HashFinal(state, NULL)
#define Keccak_HashSqueeze_SHAKE(state, output, outlen) Keccak_HashSqueeze(state, output, (outlen) * 8)
#define Keccak_HashUpdate_SHA3(state, input, inlen)     Keccak_HashUpdate(state, input, (inlen) * 8)
#define Keccak_HashFinal_SHA3(state, digest)            Keccak_HashFinal(state, digest)

typedef Keccak_HashInstance sig_perk_prg_state_t;
typedef Keccak_HashInstance sig_perk_hash_state_t;

/**
 * @brief Initialize a PRNG
 *        absorb the salt if not NULL and seed
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] salt a string containing the salt. If Null no salt is absorbed.
 * @param [in] seed a string containing the seed. If Null no seed is absorbed.
 */
void sig_perk_prg_init(sig_perk_prg_state_t *state, const salt_t salt, const seed_t seed);

/**
 * @brief absorb additional data
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] data data to be absorbed.
 * @param [in] data_size size of the data buffer.
 */
void sig_perk_prg_update(sig_perk_prg_state_t *state, const uint8_t *data, const size_t data_size);

/**
 * @brief finalize the PRG absorbing the domain separator
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [in] domain a byte that is the domain separator.
 */
void sig_perk_prg_final(sig_perk_prg_state_t *state, const uint8_t domain);

/**
 * @brief PRNG
 *
 * @param [out,in] state a pointer to the state of the PRNG
 * @param [out] output pinter to the buffer to be filled
 * @param [in] outlen size of the output
 */
void sig_perk_prg(sig_perk_prg_state_t *state, uint8_t *output, size_t outlen);

/**
 * @brief initialize the HASH function
 *        absorb the salt and ctr if != NULL
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [in] salt a string containing the salt. If NULL salt is not absorbed.
 * @param [in] tau pointer to uint8_t absorbed after the salt. If NULL tau is not absorbed.
 * @param [in] n pointer to uint16_t absorbed after the salt. If NULL n is not absorbed.
 */
void sig_perk_hash_init(sig_perk_hash_state_t *state, const salt_t salt, const uint8_t *tau, const uint16_t *n);

/**
 * @brief HASH update
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [in] message message to be absorbed.
 * @param [in] message_size size of the message.
 */
void sig_perk_hash_update(sig_perk_hash_state_t *state, const uint8_t *message, const size_t message_size);

/**
 * @brief output the digest for the chosen hash function (domain)
 *
 * @param [out,in] state a pointer to the state of the HASH.
 * @param [out] digest output digest.
 * @param [in] domain a byte that is the domain separator.
 */
void sig_perk_hash_final(sig_perk_hash_state_t *state, digest_t digest, const uint8_t domain);

#endif
