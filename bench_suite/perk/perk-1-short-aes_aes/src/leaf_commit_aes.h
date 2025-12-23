/**
 * @file leaf_commit_aes.h
 * @brief Seed expand functions based on AES-128 and Rijndael-256
 */

#ifndef SIG_PERK_LEAF_COMMIT_AES_H
#define SIG_PERK_LEAF_COMMIT_AES_H

#include "parameters.h"

#include <stdint.h>
#include "data_structures.h"
#include "rijndael_impl.h"

static inline void aes_commit(uint8_t dst[2 * PERK_SECURITY_BYTES], const uint8_t salt[PERK_SALT_BYTES],
                              const uint32_t idx, const uint8_t seed[PERK_SEED_BYTES]) {
    aes_expand_2blocks((node_seed_t *)dst, NULL, salt, idx, seed, Com1);
}

static inline void ggm_leaf_commit_4x(uint8_t *cmt_times4[4], const salt_t salt, const uint8_t tau4[4], uint16_t n4[4],
                                      const uint8_t *seed_times4[4]) {
    uint32_t counters = 0;

    counters = tau4[0];
    counters |= ((uint32_t)n4[0]) << 8;
    aes_commit(cmt_times4[0], salt, counters, seed_times4[0]);

    counters = tau4[1];
    counters |= ((uint32_t)n4[1]) << 8;
    aes_commit(cmt_times4[1], salt, counters, seed_times4[1]);

    counters = tau4[2];
    counters |= ((uint32_t)n4[2]) << 8;
    aes_commit(cmt_times4[2], salt, counters, seed_times4[2]);

    counters = tau4[3];
    counters |= ((uint32_t)n4[3]) << 8;
    aes_commit(cmt_times4[3], salt, counters, seed_times4[3]);
}

#endif  // SIG_PERK_LEAF_COMMIT_AES_H
