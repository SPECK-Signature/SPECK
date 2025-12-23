/**
 * @file verify_ev_expand.c
 * @brief Expansion of the elementary vectors in verification
 */

#include "verify_ev_expand.h"
#include <string.h>
#include "data_structures.h"

void sig_perk_v_tensor_product_to_ev(gf2_q_poly shares_row[PERK_PARAM_N],
                                     gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6]) {
    //
    // alg 4.17 V.TensorProduct
    gf2_q_poly q_zeta_0_1[PERK_PARAM_BASIS * PERK_PARAM_BASIS] = {0};

    for (unsigned i = 0; i < PERK_PARAM_BASIS; i++) {
        //
        unsigned j = i * PERK_PARAM_BASIS;

        gf2_q_poly_mulmod(q_zeta_0_1[j + 0], q_prime_beta_prime[(1 * 4) + i], q_prime_beta_prime[(0 * 4) + 0]);
        gf2_q_poly_mulmod(q_zeta_0_1[j + 1], q_prime_beta_prime[(1 * 4) + i], q_prime_beta_prime[(0 * 4) + 1]);
        gf2_q_poly_mulmod(q_zeta_0_1[j + 2], q_prime_beta_prime[(1 * 4) + i], q_prime_beta_prime[(0 * 4) + 2]);
        gf2_q_poly_mulmod(q_zeta_0_1[j + 3], q_prime_beta_prime[(1 * 4) + i], q_prime_beta_prime[(0 * 4) + 3]);
    }

    // alg 4.17 V.TensorProduct
    // put results in lower N shares_row elements
    const unsigned N = PERK_PARAM_BASIS * PERK_PARAM_BASIS;
    for (unsigned i = 0; i < N; i++) {
        gf2_q_poly_mulmod(shares_row[i + (0 * N)], q_zeta_0_1[i], q_prime_beta_prime[(2 * 4) + 0]);
        gf2_q_poly_mulmod(shares_row[i + (1 * N)], q_zeta_0_1[i], q_prime_beta_prime[(2 * 4) + 1]);
        gf2_q_poly_mulmod(shares_row[i + (2 * N)], q_zeta_0_1[i], q_prime_beta_prime[(2 * 4) + 2]);
        gf2_q_poly_mulmod(shares_row[i + (3 * N)], q_zeta_0_1[i], q_prime_beta_prime[(2 * 4) + 3]);
    }

#if (PERK_PARAM_N > 64)
    // alg 4.17 V.TensorProduct
    for (int i = (PERK_PARAM_N - 1); i >= 0; i--) {
        // compute from PARAM_N - 1 down to 0 to not override shares_row elements used as input
        gf2_q_poly_mulmod(shares_row[i], shares_row[i % 64], q_prime_beta_prime[(3 * 4) + (i / 64)]);
    }
#endif
}

// alg 4.22 V.Check-ElementaryVector
void v_check_elementary_vector(gf2_q_poly q_prime_e_prime[PERK_PARAM_C], const gf2_q_poly delta,
                               const gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6]) {
    //
    // alg 4.21check elementary block
    for (unsigned i = 0; i < 3; i++) {
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 0], q_prime_beta_prime[(i * 4) + 0],
                          q_prime_beta_prime[(i * 4) + 1]);
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 1], q_prime_beta_prime[(i * 4) + 2],
                          q_prime_beta_prime[(i * 4) + 3]);
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 0], q_prime_e_prime[(i * 2) + 0], delta);
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 1], q_prime_e_prime[(i * 2) + 1], delta);
    }
#if (PERK_PARAM_N > 64)
    for (unsigned i = 0; i < 3; i++) {
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 0], q_prime_e_prime[(i * 2) + 0], delta);
        gf2_q_poly_mulmod(q_prime_e_prime[(i * 2) + 1], q_prime_e_prime[(i * 2) + 1], delta);
    }
    gf2_q_poly_mulmod(q_prime_e_prime[(3 * 2) + 0], q_prime_beta_prime[(3 * 4) + 0], q_prime_beta_prime[(3 * 4) + 1]);
    gf2_q_poly_mulmod(q_prime_e_prime[(3 * 2) + 0], q_prime_e_prime[(3 * 2) + 0], delta);
    gf2_q_poly_mulmod(q_prime_e_prime[(3 * 2) + 0], q_prime_e_prime[(3 * 2) + 0], delta);

#endif
}
