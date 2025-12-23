
/**
 * @file verbose.c
 * @brief Implementation of function for printing intermediate values (VERBOSE mode)
 */

#include "verbose.h"
#include <stdio.h>
#include "api.h"
#include "data_structures.h"
#include "parameters.h"

void sig_perk_verbose_print_string(const char *var) {
    printf("\n\n\n\n### %s ###", var);
}

void sig_perk_verbose_print_uint8_t_array(const char *var, const uint8_t *input, uint16_t size) {
    printf("\n\n%s: ", var);
    for (uint16_t i = 0; i < size; i++) {
        printf("%02x", input[i]);
    }
}

void sig_perk_verbose_print_uint16_t_array(const char *var, const uint16_t *input, uint16_t size) {
    printf("\n\n%s:\n", var);
    for (uint16_t i = 0; i < size; i++) {
        printf("%s[%u] = %04" PRIx16 "\n", var, i, input[i]);
    }
}

void sig_perk_verbose_print_perm(const char *var, const uint8_t *perm, uint16_t n) {
    printf("\n\n%s:\n", var);
    for (uint16_t i = 0; i < n; i++) {
        printf("%s[%u] = %u\n", var, i, (unsigned)perm[i]);
    }
    putchar('\n');
}

void sig_perk_verbose_print_sig_perk_mat_t(const char *var, const sig_perk_mat_t mat) {
    printf("\n\n%s:\n", var);
    for (uint16_t i = 0; i < PERK_PARAM_M; i++) {
        for (uint16_t j = 0; j < PERK_PARAM_N; j++) {
            printf("%04" PRIx16 " ", mat[i][j]);
        }
        printf("\n");
    }
}

void sig_perk_verbose_print_f_poly_t(const sig_perk_f_poly_t *a) {
    printf("\n\na\n");
    printf("u:");
    for (size_t i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        printf("%04" PRIx16 " ", a->u[i]);
    }
    printf("\n");

    for (size_t j = 0; j < PERK_PARAM_D; j++) {
        printf("v[%zu]:\n", j);
        for (size_t i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
            printf("%04" PRIx16 " ", a->v[j][i]);
        }
        printf("\n");
    }
}

void sig_perk_verbose_print_ctr(uint64_t ctr) {
    printf("\n\nctr = 0x%016" PRIx64 "\n", ctr);
}

void sig_perk_verbose_print_pdecom_seeds(const node_seed_t pdecom[PERK_PARAM_T_OPEN]) {
    printf("\n\npdecom\n");
    for (size_t i = 0; i < PERK_PARAM_T_OPEN; i++) {
        printf("pdecom[%zu]: ", i);
        for (size_t j = 0; j < PERK_SEED_BYTES; j++) {
            printf("%02x", pdecom[i][j]);
        }
        printf("\n");
    }
}

void sig_perk_verbose_print_i_vect(const i_vect_t v) {
    printf("\n\ni_vect\n");
    for (size_t i = 0; i < PERK_PARAM_TAU; i++) {
        printf("i_vect[%zu] = %u\n", i, v[i]);
    }
}

void sig_perk_verbose_print_commitments(const cmt_t com_e_i[PERK_PARAM_TAU]) {
    printf("\n\ncom_e_i\n");
    for (size_t i = 0; i < PERK_PARAM_TAU; i++) {
        printf("com_e_i[%zu]: ", i);
        for (size_t j = 0; j < PERK_COMMITMENT_BYTES; j++) {
            printf("%02x", com_e_i[i][j]);
        }
        printf("\n");
    }
}

void sig_perk_verbose_print_signature_raw(const uint8_t *m, uint64_t mlen, const uint8_t *signature) {
    sig_perk_verbose_print_uint8_t_array("m", m, mlen);
    printf("\n\nsm(CRYPTO_BYTES):");
    for (uint16_t i = 0; i < CRYPTO_BYTES; ++i) {
        if (i % 32 == 0)
            printf("\n");
        printf("%02x", signature[i]);
    }
    printf("\n\n");
}
