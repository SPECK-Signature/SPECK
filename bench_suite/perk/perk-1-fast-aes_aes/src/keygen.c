
/**
 * @file keygen.c
 * @brief Implementation of key generation
 */

#include "keygen.h"
#include "api.h"
#include "data_structures.h"
#include "gf_arithmetic.h"
#include "parameters.h"
#include "parsing.h"
#include "permutation.h"
#include "randombytes.h"
#include "stdint.h"
#include "symmetric.h"
#include "verbose.h"

#ifdef OBSOLETE
void sig_perk_mat_set_random(sig_perk_mat_t matrix, const seed_t seed) {
    sig_perk_prg_state_t prg = {0};
    sig_perk_prg_init(&prg, NULL, seed);
    sig_perk_prg_final(&prg, H0);
    uint64_t rnd_buff[(PERK_PARAM_M * PERK_PARAM_N * PERK_PARAM_Q + 64) / 64] = {0};
    // generate random buffer
    sig_perk_prg(&prg, (uint8_t *)rnd_buff, sizeof(rnd_buff));

    int start = 0, buff_count = 0;
    for (int i = 0; i < PERK_PARAM_M; i++) {
        for (int j = 0; j < PERK_PARAM_N; j++) {
            if (start <= (64 - PERK_PARAM_Q)) {
                matrix[i][j] = (uint16_t)((rnd_buff[buff_count] >> start) & GF2_Q_FIELD_MUL_ORDER);
            } else {
                int sleft = 64 - (PERK_PARAM_Q - (64 - start));
                int sright = (sleft - (64 - start));
                matrix[i][j] =
                    (uint16_t)(rnd_buff[buff_count] >> start) ^ ((rnd_buff[buff_count + 1] << sleft) >> sright);
            }
            start += PERK_PARAM_Q;
            if (start > 63) {
                buff_count++;
                start -= 64;
            }
        }
    }
}

// Compute a basis of the right kernel of a matrix in RREF.
uint8_t sig_perk_right_kernel(sig_perk_vec_t null_basis[PERK_PARAM_N - PERK_PARAM_M], sig_perk_mat_t rref_matrix,
                              uint16_t pivots[PERK_PARAM_M]) {
    int col_free[PERK_PARAM_N - PERK_PARAM_M] = {0};

    // Find feee variables
    int count_col_free = 0;
    for (int i = 0; i < PERK_PARAM_N; i++) {
        int is_pivot = 0;
        for (int j = 0; j < PERK_PARAM_M; j++) {
            if (i == pivots[j]) {
                is_pivot = 1;
                break;
            }
        }
        if (!is_pivot) {
            col_free[count_col_free++] = i;
        }
    }

    if (count_col_free != PERK_PARAM_N - PERK_PARAM_M) {
        return PERK_FAILURE;
    }

    // Find basis of null-space (right-kernel)
    memset(null_basis, 0, sizeof(sig_perk_vec_t) * (PERK_PARAM_N - PERK_PARAM_M));
    for (int i = 0; i < PERK_PARAM_N - PERK_PARAM_M; i++) {
        null_basis[i][col_free[i]] = 1;

        // Solve for the pivot variables
        for (int j = 0; j < PERK_PARAM_M; j++) {
            null_basis[i][pivots[j]] = rref_matrix[j][col_free[i]];
        }
    }
    return PERK_SUCCESS;
}
#endif

uint16_t read_11bit_in_64bytearray(uint64_t *buffer, uint16_t pos, uint16_t index) {
    uint16_t val = 0;
    if (pos <= (64 - PERK_PARAM_Q)) {
        val = (uint16_t)((buffer[index] >> pos) & GF2_Q_FIELD_MUL_ORDER);
    } else {
        uint16_t sleft = 64 - (PERK_PARAM_Q - (64 - pos));
        uint16_t sright = (sleft - (64 - pos));
        val = (uint16_t)(buffer[index] >> pos) ^ ((buffer[index + 1] << sleft) >> sright);
    }
    return val &= GF2_Q_FIELD_MUL_ORDER;
}

// Sample a matrix in RREF
void sig_perk_mat_set_random_rref(sig_perk_mat_t matrix, const seed_t seed) {
    sig_perk_prg_state_t prg = {0};
    sig_perk_prg_init(&prg, NULL, seed);
    sig_perk_prg_final(&prg, H0_0);
    uint64_t rnd_buff[(PERK_PARAM_M * (PERK_PARAM_N - PERK_PARAM_M) * PERK_PARAM_Q + 63) / 64] = {0};
    // generate random buffer
    sig_perk_prg(&prg, (uint8_t *)rnd_buff, sizeof(rnd_buff));

    memset(matrix, 0, sizeof(sig_perk_mat_t));
    int pos = 0, buff_infex = 0;
    for (int i = 0; i < PERK_PARAM_M; i++) {
        matrix[i][i] = 1;
        for (int j = PERK_PARAM_M; j < PERK_PARAM_N; j++) {
            matrix[i][j] = read_11bit_in_64bytearray(rnd_buff, pos, buff_infex);
            pos += PERK_PARAM_Q;
            if (pos > 63) {
                buff_infex++;
                pos -= 64;
            }
        }
    }
}

// Compute a basis of the right kernel of a matrix in RREF.
void sig_perk_right_kernel(sig_perk_vec_t null_basis[PERK_PARAM_N - PERK_PARAM_M], sig_perk_mat_t rref_matrix) {
    memset(null_basis, 0, sizeof(sig_perk_vec_t) * (PERK_PARAM_N - PERK_PARAM_M));
    for (int i = 0; i < PERK_PARAM_N - PERK_PARAM_M; i++) {
        // Set identity in the second block of the matrix
        null_basis[i][PERK_PARAM_M + i] = 1;

        // Set the free part in the first block of the matrix
        for (int j = 0; j < PERK_PARAM_M; j++) {
            null_basis[i][j] = rref_matrix[j][PERK_PARAM_M + i];
        }
    }
}

// Sample element in the left-kernel (null-space) of the matrix given in RREF
void sig_perk_sample_kernel_element(sig_perk_vec_t kernel_vec, sig_perk_mat_t mat_H, seed_t seed) {
    sig_perk_vec_t null_basis[PERK_PARAM_N - PERK_PARAM_M] = {0};
    uint16_t coeffs[PERK_PARAM_N - PERK_PARAM_M] = {0};
    uint64_t rnd_buff[((PERK_PARAM_N - PERK_PARAM_M) * PERK_PARAM_Q + 63) / 64] = {0};

    // Compute a generator of the right kernel of the matrix
    sig_perk_right_kernel(null_basis, mat_H);

    // Sample a random combination of the kernel basis elements
    sig_perk_prg_state_t prg = {0};
    sig_perk_prg_init(&prg, NULL, seed);
    sig_perk_prg_final(&prg, H0_1);
    sig_perk_prg(&prg, (uint8_t *)rnd_buff, sizeof(rnd_buff));

    // Read 11 random bits at a time
    int pos = 0, buff_index = 0;
    for (int i = 0; i < PERK_PARAM_N - PERK_PARAM_M; i++) {
        coeffs[i] = read_11bit_in_64bytearray(rnd_buff, pos, buff_index);
        pos += PERK_PARAM_Q;
        if (pos > 63) {
            buff_index++;
            pos -= 64;
        }
    }

    // Compute the resulting secret vector
    memset(kernel_vec, 0, sizeof(sig_perk_vec_t));
    for (int i = 0; i < PERK_PARAM_N - PERK_PARAM_M; i++) {
        for (int j = 0; j < PERK_PARAM_N; j++) {
            uint16_t tmp;
            sig_perk_gf2_q_mul(&tmp, coeffs[i], null_basis[i][j]);
            kernel_vec[j] ^= tmp;
        }
    }

    memset(coeffs, 0, sizeof(uint16_t) * (PERK_PARAM_N - PERK_PARAM_M));
}

uint8_t sig_perk_generate_keypair(sig_perk_public_key_t *pk, sig_perk_private_key_t *sk) {
    seed_t seed_kernel = {0};

    randombytes(pk->H_seed, sizeof(seed_t));
    randombytes(sk->perm_seed, sizeof(seed_t));
    randombytes(seed_kernel, sizeof(seed_t));

    sig_perk_mat_set_random_rref(pk->H, pk->H_seed);
    SIG_PERK_VERBOSE_PRINT_sig_perk_mat_t("H", (const uint16_t(*)[PERK_PARAM_N])pk->H);

    // Sample kernel vector
    sig_perk_vec_t kernel_vec = {0};
    sig_perk_sample_kernel_element(kernel_vec, pk->H, seed_kernel);
    SIG_PERK_VERBOSE_PRINT_uint16_t_array("x'", kernel_vec, PERK_PARAM_N);

    // Sample permutation
    sig_perk_perm_set_random(sk->p, sk->perm_seed);
    SIG_PERK_VERBOSE_PRINT_perm("π", sk->p, PERK_PARAM_N);

    // Invert permutation
    perm_t p_inverse;
    sig_perk_perm_inverse(p_inverse, sk->p);

    // Permute kernel vector
    sig_perk_perm_vect_permute(pk->x, p_inverse, kernel_vec);
    SIG_PERK_VERBOSE_PRINT_uint16_t_array("x", pk->x, PERK_PARAM_N);

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("H_seed", pk->H_seed, PERK_SEED_BYTES);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("perm_seed", sk->perm_seed, PERK_SEED_BYTES);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("kernel_seed", seed_kernel, sizeof(seed_t));

    // Delete kernel vector from memory
    memset(seed_kernel, 0, sizeof(seed_t));
    memset(kernel_vec, 0, sizeof(sig_perk_vec_t));

    return PERK_SUCCESS;
}
