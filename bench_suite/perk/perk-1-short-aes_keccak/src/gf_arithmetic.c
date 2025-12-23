#include "gf_arithmetic.h"
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

// GF2_lambda

uint8_t sig_perk_gf2_lambda_elt_get_coefficient(const gf2_lambda_elt e, uint32_t index) {
    uint64_t w = 0;

    for (uint8_t i = 0; i < GF2_LAMBDA_ELT_SIZE; i++) {
        w |= -((i ^ (index >> 6)) == 0) & e[i];
    }

    return (w >> (index & 63)) & 1;
}

void sig_perk_gf2_lambda_elt_print(const gf2_lambda_elt e) {
    printf("[");
    for (unsigned i = 0; i < GF2_LAMBDA_ELT_SIZE; i++) {
        printf(" %016" PRIx64, e[i]);
    }
    printf(" ]");
}

void sig_perk_gf2_lambda_elt_ur_print(const gf2_lambda_elt_ur e) {
    printf("[");
    for (unsigned i = 0; i < GF2_LAMBDA_ELT_UR_SIZE; i++) {
        printf(" %016" PRIx64, e[i]);
    }
    printf(" ]");
}

void sig_perk_gf2_lambda_from_bytes(gf2_lambda_elt e, uint8_t bytes_array[GF2_LAMBDA_ELT_UINT8_SIZE]) {
    memcpy(e, bytes_array, sizeof(uint64_t) * GF2_LAMBDA_ELT_SIZE);
}

void sig_perk_gf2_lambda_to_bytes(uint8_t bytes_array[GF2_LAMBDA_ELT_UINT8_SIZE], gf2_lambda_elt e) {
    memcpy(bytes_array, e, GF2_LAMBDA_ELT_UINT8_SIZE);
}

void sig_perk_gf2_lambda_from_gf2_64(gf2_lambda_elt o, const gf2_64_elt e) {
    memcpy(o, e, sizeof(gf2_64_elt));
}

void sig_perk_gf2_lambda_set(gf2_lambda_elt o, const gf2_lambda_elt e) {
    for (size_t i = 0; i < GF2_LAMBDA_ELT_SIZE; i++) {
        o[i] = e[i];
    }
}

void sig_perk_gf2_64_from_bytes(gf2_64_elt e, uint8_t bytes_array[GF2_64_ELT_UINT8_SIZE]) {
    memcpy(e, bytes_array, sizeof(uint64_t) * GF2_64_ELT_SIZE);
}
