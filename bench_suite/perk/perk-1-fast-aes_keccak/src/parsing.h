/**
 * @file parsing.h
 * @brief Parsing functions for PERK
 */

#ifndef SIG_PERK_PARSING_H
#define SIG_PERK_PARSING_H

#include "config.h"
#include "data_structures.h"

/**
 * @brief Read n bits from sb[], starting at bit-offset (*pos) in sb[*index],
 *        then update *pos and *index as bits are consumed.
 *
 * @param sb      The input byte array
 * @param pos     Current bit offset within sb[*index] (0..7)
 * @param index   Current byte index in sb
 * @param nbits   How many bits to read
 * @return        The nbits bits read (lowest nbits bits of the returned value)
 */
static inline uint32_t sig_perk_read_n_bits_from_bytearray(const uint8_t *sb, uint16_t *pos, uint16_t *index,
                                                           uint16_t nbits) {
    uint32_t result = 0;
    uint16_t shift = 0;

    while (nbits > 0) {
        uint16_t room = 8 - *pos;
        uint16_t bits_to_read = (room < nbits) ? room : nbits;

        uint32_t chunk = (uint32_t)((sb[*index] >> *pos) & ((1U << bits_to_read) - 1));
        result |= (chunk << shift);
        shift += bits_to_read;
        nbits -= bits_to_read;
        *pos += bits_to_read;

        if (*pos == 8) {
            (*index)++;
            *pos = 0;
        }
    }
    return result;
}

void sig_perk_public_key_to_bytes(uint8_t *pk_bytes, const sig_perk_public_key_t *pk_struct);
void sig_perk_private_key_to_bytes(uint8_t *sk_bytes, const sig_perk_private_key_t *sk_struct);

int sig_perk_public_key_from_bytes(sig_perk_public_key_t *pk_struct, uint8_t const *pk_bytes);
void sig_perk_private_key_from_bytes(sig_perk_private_key_t *sk_struct, uint8_t const *sk_bytes);

/**
 * @brief Parse a signature into a string
 *
 * @param [out] sb a string containing the signature. It must be initialized to zero.
 * @param [in] signature a pointer to signature structure
 */
void sig_perk_signature_to_bytes(uint8_t sb[PERK_SIGNATURE_BYTES], const sig_perk_signature_t *signature);

/**
 * @brief Parse a signature from a string
 *
 * @param [out] signature a pointer to signature structure
 * @param [in] sb a string containing the signature
 * @return int 0 if the parsing is successful and 1 otherwise
 */
int sig_perk_signature_from_bytes(sig_perk_signature_t *signature, const uint8_t sb[PERK_SIGNATURE_BYTES]);

// mask for the possible unused bits in the public key
#define PUBLIC_KEY_PADDING_MASK ((uint8_t) ~((1 << ((PERK_PARAM_Q * PERK_PARAM_N - 1) % 8 + 1)) - 1))

#define SIGNATURE_PADDING_BITS (PERK_SIGNATURE_BYTES * 8u - PERK_SIGNATURE_BITS)
#define SIGNATURE_PADDING_MASK ~((1 << (8 - (SIGNATURE_PADDING_BITS % 8))) - 1)

#endif  // SIG_PERK_PARSING_H
