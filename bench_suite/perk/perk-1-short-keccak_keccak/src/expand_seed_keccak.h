
/**
 * @file expand_seed_keccak.h
 * @brief Implementation of the PRG for the ggm tree
 */

#ifndef SIG_PERK_EXPAND_SEED_KECCAK_H
#define SIG_PERK_EXPAND_SEED_KECCAK_H

#include "ggm_tree.h"
#include "parameters.h"
#include "symmetric.h"
#include "symmetric_times4.h"

static inline void ggm_expand_seed(node_seed_t dst[2], const salt_t salt, const uint16_t idx, const node_seed_t seed) {
    sig_perk_hash_state_t state_PRG1 = {0};

    sig_perk_hash_init(&state_PRG1, salt, NULL, &idx);
    sig_perk_hash_update(&state_PRG1, seed, sizeof(node_seed_t));
    sig_perk_hash_final(&state_PRG1, dst[0], PRG1);
}

static inline void ggm_expand_seed_4x(node_seed_t dst[8], const salt_t salt, const uint16_t idx,
                                      const node_seed_t seed[4]) {
    sig_perk_hash_times4_state_t state_PRG1 = {0};

    const uint16_t counters[4] = {idx + 0, idx + 1, idx + 2, idx + 3};
    const uint8_t *seed4[] = {seed[0], seed[1], seed[2], seed[3]};
    uint8_t *dst4[] = {dst[0], dst[2], dst[4], dst[6]};

    sig_perk_hash_times4_init(&state_PRG1, salt, NULL, counters);
    sig_perk_hash_times4_update(&state_PRG1, seed4, sizeof(node_seed_t));
    sig_perk_hash_times4_final(&state_PRG1, dst4, PRG1);
}

#endif  // SIG_PERK_EXPAND_SEED_KECCAK_H
