
/**
 * @file symmetric_times4.c
 * @brief Implementation of the symmetric times4 functions
 */

#include "symmetric_times4.h"
#include "parameters.h"

void sig_perk_prg_times4_init(sig_perk_prg_times4_state_t *state, const salt_t salt, const uint8_t *seed4[4]) {
    Keccak_HashInitializetimes4_SHAKE(state);
    if (salt != NULL) {
        const uint8_t *salt4[] = {salt, salt, salt, salt};
        Keccak_HashUpdatetimes4_SHAKE(state, salt4, sizeof(salt_t));
    }
    if (seed4 != NULL) {
        Keccak_HashUpdatetimes4_SHAKE(state, seed4, sizeof(seed_t));
    }
}

void sig_perk_prg_times4_update(sig_perk_prg_times4_state_t *state, const uint8_t *data4[4], const size_t data_size) {
    Keccak_HashUpdatetimes4_SHAKE(state, data4, data_size);
}

void sig_perk_prg_times4_final(sig_perk_prg_times4_state_t *state, const uint8_t domain) {
    const uint8_t *domain4[] = {&domain, &domain, &domain, &domain};
    Keccak_HashUpdatetimes4_SHAKE(state, domain4, 1);
    Keccak_HashFinaltimes4_SHAKE(state);
}

void sig_perk_prg_times4(sig_perk_prg_times4_state_t *state, uint8_t *output4[4], size_t outlen) {
    Keccak_HashSqueezetimes4_SHAKE(state, output4, outlen);
}

void sig_perk_hash_times4_init(sig_perk_hash_times4_state_t *state, const salt_t salt, const uint8_t tau4[4],
                               const uint16_t n4[4]) {
    Keccak_HashInitializetimes4_SHA3(state);
    if (salt != NULL) {
        const uint8_t *salt4[] = {salt, salt, salt, salt};
        Keccak_HashUpdatetimes4_SHA3(state, salt4, sizeof(salt_t));
    }

    uint8_t counters[4][3];
    int j = 0;
    if (tau4 != NULL) {
        for (int i = 0; i < 4; i++) {
            counters[i][j] = tau4[i];
        }
        j++;
    }
    if (n4 != NULL) {
        for (int i = 0; i < 4; i++) {
            counters[i][j] = (uint8_t)n4[i];
        }
        j++;
        for (int i = 0; i < 4; i++) {
            counters[i][j] = (uint8_t)(n4[i] >> 8);
        }
        j++;
    }
    if (j != 0) {
        const uint8_t *counters4[] = {counters[0], counters[1], counters[2], counters[3]};
        Keccak_HashUpdatetimes4_SHA3(state, counters4, j);
    }
}

void sig_perk_hash_times4_update(sig_perk_hash_times4_state_t *state, const uint8_t *message4[4],
                                 const size_t message_size) {
    Keccak_HashUpdatetimes4_SHA3(state, message4, message_size);
}

void sig_perk_hash_times4_final(sig_perk_hash_times4_state_t *state, uint8_t *digest4[4], const uint8_t domain) {
    const uint8_t *domain4[] = {&domain, &domain, &domain, &domain};
    Keccak_HashUpdatetimes4_SHA3(state, domain4, 1);
    Keccak_HashFinaltimes4_SHA3(state, digest4);
}
