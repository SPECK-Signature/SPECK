
/**
 * @file leaf_commit_keccak.h
 * @brief Implementation of the PRG for the ggm tree
 */

#ifndef SIG_PERK_LEAF_COMMIT_KECCAK_H
#define SIG_PERK_LEAF_COMMIT_KECCAK_H

#include "ggm_tree.h"
#include "parameters.h"
#include "symmetric.h"
#include "symmetric_times4.h"

static inline void ggm_leaf_commit_4x(uint8_t *cmt_times4[4], const salt_t salt, const uint8_t tau4[4], uint16_t n4[4],
                                      const uint8_t *seed_times4[4]) {
    sig_perk_hash_times4_state_t state_Com1 = {0};

    sig_perk_hash_times4_init(&state_Com1, salt, tau4, n4);
    sig_perk_hash_times4_update(&state_Com1, seed_times4, sizeof(node_seed_t));
    sig_perk_hash_times4_final(&state_Com1, cmt_times4, Com1);
}

#endif  // SIG_PERK_LEAF_COMMIT_KECCAK_H
