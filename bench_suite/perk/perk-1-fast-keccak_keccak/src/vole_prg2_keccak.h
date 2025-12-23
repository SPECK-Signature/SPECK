/**
 * @file vole_prg2_keccak.h
 * @brief implementation of PRG2 for convert_to_vole
 */

#ifndef SIG_PERK_VOLE_PRG2_KECCAK_H
#define SIG_PERK_VOLE_PRG2_KECCAK_H

#include <stdint.h>
#include "data_structures.h"
#include "parameters.h"
#include "symmetric.h"
#include "symmetric_times4.h"

static inline void sig_perk_vole_PRG2(uint8_t* out, const salt_t salt, const uint8_t* seed) {
    sig_perk_prg_state_t state = {0};

    sig_perk_prg_init(&state, salt, seed);
    sig_perk_prg_final(&state, PRG2);
    sig_perk_prg(&state, out, sizeof(perk_vole_data_t));
}

static inline void sig_perk_vole_PRG2_times4(uint8_t* out[4], const salt_t salt, const uint8_t* seed4[4]) {
    sig_perk_prg_times4_state_t state4 = {0};

    sig_perk_prg_times4_init(&state4, salt, seed4);
    sig_perk_prg_times4_final(&state4, PRG2);
    sig_perk_prg_times4(&state4, out, sizeof(perk_vole_data_t));
}

#endif  // SIG_PERK_VOLE_PRG2_KECCAK_H
