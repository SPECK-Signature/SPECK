/**
 * @file vole_prg2_aes.h
 * @brief implementation of PRG2 for convert_to_vole
 */

#ifndef SIG_PERK_VOLE_PRG2_AES_H
#define SIG_PERK_VOLE_PRG2_AES_H

#include <stdint.h>
#include "data_structures.h"
#include "expand_seed_aes.h"
#include "parameters.h"
#include "rijndael_impl.h"

#define PERK_PRG2_BLOCK_BYTES PERK_SEED_BYTES

static inline void expand_share(uint8_t (*dst)[PERK_PRG2_BLOCK_BYTES], const salt_t salt, const seed_t seed,
                                uint8_t len) {
    // This function assumes dst has capacity len, and that the len is at most 255

    uint8_t msg[BLOCK_BYTES] __attribute__((aligned(BLOCK_BYTES))) = {0};
    round_keys_t key = {0};

    aes_expand_2blocks((node_seed_t*)dst, &key, salt, 0, seed, PRG2);

    // salt ^ (domain_separator || idx || 0)
    memcpy(msg, salt, sizeof(salt_t) / 2);
    uint8_t msg0 = msg[0];
    msg[5] ^= PRG2;

    for (uint8_t i = 2; i < len; i++) {
        msg[0] = msg0 ^ i;

#if (PERK_SECURITY_BYTES < BLOCK_BYTES)
        uint8_t output[BLOCK_BYTES] __attribute__((aligned(32))) = {0};
#else
        uint8_t* output = dst[i];
#endif

        encrypt(output, msg, &key);

#if (PERK_SECURITY_BYTES < BLOCK_BYTES)
        memcpy(dst[i], output, PERK_PRG2_BLOCK_BYTES);  // copy only 24 bytes of output[0]
#endif
    }
}

#define n_blocks ((sizeof(perk_vole_data_t) + PERK_PRG2_BLOCK_BYTES - 1) / PERK_PRG2_BLOCK_BYTES)
static inline void sig_perk_vole_PRG2(uint8_t* out, const salt_t salt, const seed_t seed) {
    uint8_t buffer[n_blocks][PERK_PRG2_BLOCK_BYTES] __attribute__((aligned(32))) = {0};

    expand_share(buffer, salt, seed, n_blocks);
    memcpy(out, buffer, sizeof(perk_vole_data_t));
}

static inline void sig_perk_vole_PRG2_times4(uint8_t* out[4], const salt_t salt, const uint8_t* seed4[4]) {
    sig_perk_vole_PRG2(out[0], salt, seed4[0]);
    sig_perk_vole_PRG2(out[1], salt, seed4[1]);
    sig_perk_vole_PRG2(out[2], salt, seed4[2]);
    sig_perk_vole_PRG2(out[3], salt, seed4[3]);
}

#endif  // SIG_PERK_VOLE_PRG2_AES_H
