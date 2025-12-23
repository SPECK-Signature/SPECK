/**
 * @file expand_seed_aes.h
 * @brief Seed expand functions based on AES-128 and Rijndael-256
 */

#ifndef SIG_PERK_EXPAND_SEED_AES_H
#define SIG_PERK_EXPAND_SEED_AES_H

#include "parameters.h"

#include <stdint.h>
#include "data_structures.h"
#include "rijndael_impl.h"

static inline void ggm_expand_seed(node_seed_t dst[2], const salt_t salt, const uint32_t idx, const node_seed_t seed) {
    aes_expand_2blocks(dst, NULL, salt, idx, seed, PRG1);
}

static inline void ggm_expand_seed_4x(node_seed_t dst[8], const salt_t salt, const uint16_t idx,
                                      const node_seed_t seed[4]) {
    ggm_expand_seed(dst + 0, salt, idx + 0, seed[0]);
    ggm_expand_seed(dst + 2, salt, idx + 1, seed[1]);
    ggm_expand_seed(dst + 4, salt, idx + 2, seed[2]);
    ggm_expand_seed(dst + 6, salt, idx + 3, seed[3]);
}

#endif  // SIG_PERK_EXPAND_SEED_AES_H
