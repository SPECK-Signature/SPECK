/**
 * @file parsing.c
 * @brief Parsing functions for PERK
 */

#include "parsing.h"
#include "keygen.h"

#include <stdint.h>

/**
 * @brief Store n bits from val into sb[], starting at bit-offset (*pos)
 *        in sb[*index], then update *pos and *index as bits are consumed.
 *
 * @param sb      Byte array pointer (out)
 * @param pos     Current bit offset within sb[*index] (0..7)
 * @param index   Current byte index in sb
 * @param val     Input bits (lowest n bits are used)
 * @param nbits   How many bits from val to write
 */
static inline void sig_perk_store_n_bits_in_bytearray(uint8_t *sb, uint16_t *pos, uint16_t *index, uint32_t val,
                                                      uint16_t nbits) {
    val &= (1U << nbits) - 1;
    while (nbits > 0) {
        uint16_t room = 8 - *pos;
        uint16_t bits_to_write = (room < nbits) ? room : nbits;
        uint32_t chunk = val & ((1U << bits_to_write) - 1);
        sb[*index] ^= (uint8_t)(chunk << *pos);
        val >>= bits_to_write;
        *pos += bits_to_write;
        nbits -= bits_to_write;

        if (*pos == 8) {
            (*index)++;
            *pos = 0;
        }
    }
}

/**
 * @brief Copy m bits from *src, starting at byte srcIndex and bit srcPos,
 * to *dst at byte dstIndex and bit dstPos
 *
 * @param dst pointer to destination array
 * @param dstIndex pointer to destination byte index
 * @param dstPos pointer to destination bit index
 * @param src pointer to source array
 * @param srcIndex pointer to source byte index
 * @param srcPos pointer to source bit index
 * @param m number of bits to copy
 */
static inline void sig_perk_copy_bits_from_array_to_array(uint8_t *dst, uint16_t *dstIndex, uint16_t *dstPos,
                                                          const uint8_t *src, uint16_t *srcIndex, uint16_t *srcPos,
                                                          uint16_t m) {
    while (m > 0) {
        size_t bitsLeftInSrc = 8 - *srcPos;
        size_t bitsLeftInDst = 8 - *dstPos;

        size_t bitsToTransfer = (m < bitsLeftInSrc) ? m : bitsLeftInSrc;
        if (bitsToTransfer > bitsLeftInDst) {
            bitsToTransfer = bitsLeftInDst;
        }
        uint8_t chunk = (uint8_t)((src[*srcIndex] >> *srcPos) & ((1U << bitsToTransfer) - 1));

        dst[*dstIndex] ^= (uint8_t)(chunk << *dstPos);

        *srcPos += (uint8_t)bitsToTransfer;
        if (*srcPos >= 8) {
            *srcPos -= 8;  // or simply *srcPos = 0
            (*srcIndex)++;
        }

        *dstPos += (uint8_t)bitsToTransfer;
        if (*dstPos >= 8) {
            *dstPos -= 8;  // or simply *dstPos = 0
            (*dstIndex)++;
        }

        m -= bitsToTransfer;
    }
}

void sig_perk_public_key_to_bytes(uint8_t *pk_bytes, const sig_perk_public_key_t *pk_struct) {
    memset(pk_bytes, 0, PERK_PUBLIC_KEY_BYTES);
    uint8_t *p_pk_bytes = pk_bytes;
    memcpy(p_pk_bytes, pk_struct->H_seed, PERK_SEED_BYTES);

    p_pk_bytes += PERK_SEED_BYTES;

    // Copy 11 bits at time
    uint16_t index = 0, pos = 0;
    for (int i = 0; i < PERK_PARAM_N; i++) {
        sig_perk_store_n_bits_in_bytearray(p_pk_bytes, &pos, &index, pk_struct->x[i], 11);
    }
}

void sig_perk_private_key_to_bytes(uint8_t *sk_bytes, const sig_perk_private_key_t *sk_struct) {
    memcpy(sk_bytes, sk_struct->perm_seed, PERK_SEED_BYTES);
}

int sig_perk_public_key_from_bytes(sig_perk_public_key_t *pk_struct, uint8_t const *pk_bytes) {
// we have spare bits
#if (((PERK_PARAM_Q * PERK_PARAM_N) % 8) != 0)
    if (pk_bytes[PERK_PUBLIC_KEY_BYTES - 1] & PUBLIC_KEY_PADDING_MASK) {
        return PERK_FAILURE;
    }
#endif

    uint8_t const *p_pk_bytes = pk_bytes;
    memcpy(pk_struct->H_seed, p_pk_bytes, PERK_SEED_BYTES);
    p_pk_bytes += PERK_SEED_BYTES;

    uint16_t pos = 0, index = 0;
    for (int i = 0; i < PERK_PARAM_N; i++) {
        pk_struct->x[i] = sig_perk_read_n_bits_from_bytearray(p_pk_bytes, &pos, &index, PERK_PARAM_Q);
    }
    return PERK_SUCCESS;
}

void sig_perk_private_key_from_bytes(sig_perk_private_key_t *sk_struct, uint8_t const *sk_bytes) {
    memcpy(sk_struct->perm_seed, sk_bytes, PERK_SEED_BYTES);
}

void sig_perk_signature_to_bytes(uint8_t sb[PERK_SIGNATURE_BYTES], const sig_perk_signature_t *signature) {
    memset(sb, 0, PERK_SIGNATURE_BYTES);
    uint8_t *psb = sb;
    memcpy(psb, signature->c, sizeof(signature->c));
    psb += sizeof(signature->c);
    memcpy(psb, signature->u_tilde, sizeof(signature->u_tilde));
    psb += sizeof(signature->u_tilde);
    memcpy(psb, signature->pdecom, sizeof(signature->pdecom));
    psb += sizeof(signature->pdecom);
    memcpy(psb, signature->com_e_i, sizeof(signature->com_e_i));
    psb += sizeof(signature->com_e_i);
    memcpy(psb, &signature->ctr, sizeof(uint64_t));
    psb += sizeof(uint64_t);
    memcpy(psb, signature->salt, sizeof(signature->salt));
    psb += sizeof(signature->salt);
    uint16_t pos = 0;
    uint16_t index = 0;

    for (int i = 0; i < PERK_PARAM_N; i++) {
        sig_perk_store_n_bits_in_bytearray(psb, &pos, &index, signature->t[i], PERK_PARAM_L_ROW);
    }

    for (int i = 0; i < PERK_PARAM_D; i++) {
        for (int j = 0; j < PERK_TOWER_FIELD_EXT; j++) {
            sig_perk_store_n_bits_in_bytearray(psb, &pos, &index, signature->a.v[i][j], PERK_PARAM_Q);
        }
    }

    uint16_t srcIndex = 0, srcPos = 0;

    // No need to send the last PERK_PARAM_W bits as they are always zero
    sig_perk_copy_bits_from_array_to_array(psb, &index, &pos, signature->ch3, &srcIndex, &srcPos,
                                           PERK_CHALL_3_BITS - PERK_PARAM_W);
}

int sig_perk_signature_from_bytes(sig_perk_signature_t *signature, const uint8_t sb[PERK_SIGNATURE_BYTES]) {
    // Check that the padding bits are zero
#if (SIGNATURE_PADDING_BITS != 0)
    if (sb[PERK_SIGNATURE_BYTES - 1] & (uint8_t)SIGNATURE_PADDING_MASK) {
        return PERK_FAILURE;
    }
#endif

    uint8_t *psb = (uint8_t *)sb;
    memcpy(signature->c, psb, sizeof(signature->c));
    psb += sizeof(signature->c);
    memcpy(signature->u_tilde, psb, sizeof(signature->u_tilde));
    psb += sizeof(signature->u_tilde);
    memcpy(signature->pdecom, psb, sizeof(signature->pdecom));
    psb += sizeof(signature->pdecom);
    memcpy(signature->com_e_i, psb, sizeof(signature->com_e_i));
    psb += sizeof(signature->com_e_i);
    memcpy(&signature->ctr, psb, sizeof(uint64_t));
    psb += sizeof(uint64_t);
    memcpy(signature->salt, psb, sizeof(signature->salt));
    psb += sizeof(signature->salt);
    uint16_t pos = 0;
    uint16_t index = 0;
    for (int i = 0; i < PERK_PARAM_N; i++) {
        signature->t[i] = sig_perk_read_n_bits_from_bytearray(psb, &pos, &index, PERK_PARAM_L_ROW);
    }

    for (int i = 0; i < PERK_PARAM_D; i++) {
        for (int j = 0; j < PERK_TOWER_FIELD_EXT; j++) {
            signature->a.v[i][j] = sig_perk_read_n_bits_from_bytearray(psb, &pos, &index, PERK_PARAM_Q);
        }
    }

    // The last PERK_PARAM_W bits are not received and set to zero by default
    uint16_t dstIndex = 0, dstPos = 0;
    sig_perk_copy_bits_from_array_to_array(signature->ch3, &dstIndex, &dstPos, psb, &index, &pos,
                                           PERK_CHALL_3_BITS - PERK_PARAM_W);

    return PERK_SUCCESS;
}
