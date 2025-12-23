
/**
 * @file permutation.c
 * @brief Implementation of permutation related functions
 */

#include "permutation.h"
#include <stdint.h>
#include <string.h>
#include "djbsort.h"
#include "symmetric.h"

int sig_perk_perm_gen_given_random_input(perm_t p, const uint16_t rnd_buff[PERK_PARAM_N]) {
    uint32_t buffer[PERK_PARAM_N] = {0};
    // Use 16 bits for randomness
    for (uint32_t i = 0; i < PERK_PARAM_N; i++) {
        buffer[i] = (((uint32_t)rnd_buff[i]) << 16U) | i;
    }
    // sort
    uint32_sort(buffer, PERK_PARAM_N);
    // check that no double random values were produced
    for (int i = 1; i < PERK_PARAM_N; i++) {
        if ((buffer[i - 1] >> 16U) == (buffer[i] >> 16U)) {
            return PERK_FAILURE;
        }
    }
    // extract permutation from buffer
    for (int i = 0; i < PERK_PARAM_N; i++) {
        p[i] = (uint8_t)(buffer[i]);
    }
    return PERK_SUCCESS;
}

void sig_perk_perm_set_random(perm_t p, const uint8_t seed[PERK_SEED_BYTES]) {
    uint16_t rnd_buff[PERK_PARAM_N] = {0};
    sig_perk_prg_state_t prg = {0};
    sig_perk_prg_init(&prg, NULL, seed);
    sig_perk_prg_final(&prg, H0_2);
    sig_perk_prg(&prg, (uint8_t *)rnd_buff, sizeof(rnd_buff));

    while (sig_perk_perm_gen_given_random_input(p, rnd_buff) != PERK_SUCCESS) {
        sig_perk_prg(&prg, (uint8_t *)rnd_buff, sizeof(rnd_buff));
    }
    memset(rnd_buff, 0, sizeof(rnd_buff));
}

void sig_perk_perm_inverse(perm_t o, const perm_t p) {
    uint32_t buffer[PERK_PARAM_N] = {0};
    for (int i = 0; i < PERK_PARAM_N; i++) {
        buffer[i] = (((uint32_t)p[i]) << 16U) | i;
    }
    uint32_sort(buffer, PERK_PARAM_N);

    for (int i = 0; i < PERK_PARAM_N; i++) {
        o[i] = (uint16_t)(buffer[i]);
    }
}

void sig_perk_perm_vect_permute(sig_perk_vec_t output, const perm_t p, const sig_perk_vec_t input) {
    uint32_t buffer[PERK_PARAM_N] = {0};
    for (int i = 0; i < PERK_PARAM_N; ++i) {
        buffer[i] = (((uint32_t)p[i]) << 16U) | input[i];
    }
    uint32_sort(buffer, PERK_PARAM_N);
    for (int i = 0; i < PERK_PARAM_N; ++i) {
        output[i] = (uint16_t)(buffer[i]);
    }
}
