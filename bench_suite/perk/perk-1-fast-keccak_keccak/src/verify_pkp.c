
#include "verify_pkp.h"
#include "gf_arithmetic.h"
#include "gf_poly_arithmetic.h"
#include "verify_ev_expand.h"

void sig_perk_expand_witness(uint8_t t_prime[2 * PERK_PARAM_L_ROW - 6], const uint16_t t) {
    uint16_t nb_shifts = 0;
    for (unsigned i = 0; i < 3; ++i) {
        uint16_t w_prime_i_3 = 1;
        for (unsigned j = 0; j < 3; ++j) {
            uint16_t w_prime_i_j = (t >> ((i * 3) + j)) & 1;
            w_prime_i_3 ^= (t >> ((i * 3) + j)) & 1;
            t_prime[nb_shifts] = w_prime_i_j;
            nb_shifts++;
        }
        t_prime[nb_shifts] = w_prime_i_3;
        nb_shifts++;
    }
#if (PERK_CONFIG_PARAM_SEC_LEVEL == 3 || PERK_CONFIG_PARAM_SEC_LEVEL == 5)
    uint16_t w_3_0 = 0;
    w_3_0 = ((t >> 9) & 1);
    t_prime[nb_shifts] = w_3_0;
    nb_shifts++;
    t_prime[nb_shifts] = (1 ^ w_3_0);
#endif
}

// alg 3.41 step 2 (V.VOLE-ElementaryVector)
void sig_perk_embed_masked_witness(gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6], const gf2_q_poly delta,
                                   const uint8_t t_prime[2 * PERK_PARAM_L_ROW - 6],
                                   const gf2_q_poly q[PERK_PARAM_L_ROW]) {
    // alg 3.37 V.EmbedMaskedWitnessBlock
    for (unsigned i = 0; i < 3; i++) {
        for (unsigned j = 0; j < 3; j++) {
            //
            gf2_q_poly_copy(q_prime_beta_prime[i * 4 + j], q[i * 3 + j]);
            if (t_prime[i * 4 + j] != 0) {  // multiply by t' and add
                gf2_q_poly_add(q_prime_beta_prime[i * 4 + j], q_prime_beta_prime[i * 4 + j], delta);
            }
        }
        gf2_q_poly_add(q_prime_beta_prime[i * 4 + 3], q[i * 3 + 0], q[i * 3 + 1]);
        gf2_q_poly_add(q_prime_beta_prime[i * 4 + 3], q_prime_beta_prime[i * 4 + 3], q[i * 3 + 2]);
        if (t_prime[i * 4 + 3] != 0) {  // multiply by t' and add
            gf2_q_poly_add(q_prime_beta_prime[i * 4 + 3], q_prime_beta_prime[i * 4 + 3], delta);
        }
    }
#if (PERK_CONFIG_PARAM_SEC_LEVEL == 3 || PERK_CONFIG_PARAM_SEC_LEVEL == 5)
    gf2_q_poly_copy(q_prime_beta_prime[3 * 4 + 0], q[3 * 3 + 0]);
    if (t_prime[3 * 4 + 0] != 0) {  // multiply by t' and add
        gf2_q_poly_add(q_prime_beta_prime[3 * 4 + 0], q_prime_beta_prime[3 * 4 + 0], delta);
    }
    gf2_q_poly_copy(q_prime_beta_prime[3 * 4 + 1], q[3 * 3 + 0]);
    if (t_prime[3 * 4 + 1] != 0) {  // multiply by t' and add
        gf2_q_poly_add(q_prime_beta_prime[3 * 4 + 1], q_prime_beta_prime[3 * 4 + 1], delta);
    }
#endif
}

void sig_perk_verify_compute_p_columns_check(gf2_q_poly col_check[PERK_PARAM_N],
                                             gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N], const gf2_q_poly delta) {
    // Compute delta^d
    gf2_q_poly delta_pow_d = {0};
    gf2_q_poly_expo(delta_pow_d, delta, PERK_PARAM_D);

    // Compute q_ColCheck
    for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
        gf2_q_poly_copy(col_check[j], q_z[j][0]);
        for (unsigned i = 1; i < PERK_PARAM_N; ++i) {
            gf2_q_poly_add(col_check[j], col_check[j], q_z[j][i]);
        }
        gf2_q_poly_add(col_check[j], col_check[j], delta_pow_d);
    }
}

void sig_perk_verify_compute_x_prime(gf2_q_poly q_x_prime[PERK_PARAM_N], gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N],
                                     const sig_perk_public_key_t *pk) {
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
            gf2_q_poly tmp = {0};
            gf2_q_poly_scal_mul(tmp, q_z[j][i], pk->x[j]);
            gf2_q_poly_add(q_x_prime[i], q_x_prime[i], tmp);
        }
    }
}

void sig_perk_verify_compute_y(gf2_q_poly q_y[PERK_PARAM_M], gf2_q_poly q_x_prime[PERK_PARAM_N],
                               const sig_perk_public_key_t *pk) {
    for (unsigned i = 0; i < PERK_PARAM_M; ++i) {
        for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
            gf2_q_poly tmp = {0};
            gf2_q_poly_scal_mul(tmp, q_x_prime[j], pk->H[i][j]);
            gf2_q_poly_add(q_y[i], q_y[i], tmp);
        }
    }
}

// Alg 4.19 V.VOLE-ElementaryVector(∆, t, q)
void sig_perk_verify_vole_ev(gf2_q_poly q_prime_beta_prime[2 * PERK_PARAM_L_ROW - 6], gf2_q_poly q_z[PERK_PARAM_N],
                             const gf2_q_poly delta, const uint16_t t, const gf2_q_poly q[PERK_PARAM_L_ROW]) {
    uint8_t t_prime[2 * PERK_PARAM_L_ROW - 6] = {0};
    sig_perk_expand_witness(t_prime, t);
    sig_perk_embed_masked_witness(q_prime_beta_prime, delta, t_prime, q);
    sig_perk_v_tensor_product_to_ev(q_z, q_prime_beta_prime);
}

// Alg 4.20
void sig_perk_verify_vole_permutation(gf2_q_poly q_beta[PERK_PARAM_N][2 * PERK_PARAM_L_ROW - 6],
                                      gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N], gf2_q_poly q_col_check[PERK_PARAM_N],
                                      const gf2_q_poly delta, const uint16_t t[PERK_PARAM_N],
                                      const perk_vole_data_t q[PERK_PARAM_RHO]) {
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        gf2_q_poly q_row[PERK_PARAM_L_ROW];
        for (unsigned j = 0; j < PERK_PARAM_L_ROW; j++) {
            sig_perk_v_to_tower_field(q_row[j], i * PERK_PARAM_L_ROW + j + PERK_PARAM_L_VHM, q);
        }
        sig_perk_verify_vole_ev(q_beta[i], q_z[i], delta, t[i], (const gf2_q_poly *)q_row);
    }
    sig_perk_verify_compute_p_columns_check(q_col_check, q_z, delta);
}

static inline void sig_perk_verify_merge_polynomials(
    gf2_q_poly q_f, gf2_q_poly q_col_check[PERK_PARAM_N], gf2_q_poly q_elt_vect_check[PERK_PARAM_N][PERK_PARAM_C],
    gf2_q_poly q_y[PERK_PARAM_M], gf2_q_poly alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M]) {
    // Merge ColCheck
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        gf2_q_poly tmp = {0};
        gf2_q_poly_mulmod(tmp, alpha[i], q_col_check[i]);
        gf2_q_poly_add(q_f, q_f, tmp);
    }
    // Merge ElemVecCheck
    for (unsigned i = 0; i < (PERK_PARAM_N * PERK_PARAM_C); ++i) {
        gf2_q_poly tmp = {0};
        gf2_q_poly_mulmod(tmp, alpha[PERK_PARAM_N + i], q_elt_vect_check[i / PERK_PARAM_C][i % PERK_PARAM_C]);
        gf2_q_poly_add(q_f, q_f, tmp);
    }
    // Merge y
    for (unsigned i = 0; i < PERK_PARAM_M; ++i) {
        gf2_q_poly tmp = {0};
        gf2_q_poly_mulmod(tmp, alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + i], q_y[i]);
        gf2_q_poly_add(q_f, q_f, tmp);
    }
}

// Alg 4.23 V.CheckZero
uint8_t sig_perk_verify_check_zero(const gf2_q_poly delta, gf2_q_poly q_f, const sig_perk_f_poly_t *a,
                                   const perk_vole_data_t q[]) {
    gf2_q_poly q_u_i[PERK_PARAM_D - 1] = {0};
    uint16_t indx = PERK_PARAM_L_PRIME;
    gf2_q_poly q_u_i_by_delta = {0};

    // Check degree of a
    if (0 != gf2_q_poly_is_zero(a->u)) {
        return PERK_FAILURE;
    }

    for (unsigned i = 0; i < PERK_PARAM_D - 1; ++i) {
        sig_perk_check_zero_v_to_tower_field(q_u_i[i], indx, q);
        indx += PERK_PARAM_RHO;
    }

    // Compute q_tilde
    gf2_q_poly q_tilde = {0};
    for (int i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly delta_to_i = {0};
        gf2_q_poly tmp = {0};
        gf2_q_poly_expo(delta_to_i, delta, i);
        gf2_q_poly_mulmod(tmp, a->v[i], delta_to_i);
        gf2_q_poly_add(q_tilde, q_tilde, tmp);
    }

    // Compute q_u_i by delta
    for (int i = 0; i < PERK_PARAM_D - 1; ++i) {
        gf2_q_poly delta_to_i = {0};
        gf2_q_poly tmp = {0};
        gf2_q_poly_expo(delta_to_i, delta, i);
        gf2_q_poly_mulmod(tmp, q_u_i[i], delta_to_i);
        gf2_q_poly_add(q_u_i_by_delta, q_u_i_by_delta, tmp);
    }

    // Compute q
    gf2_q_poly q_val = {0};
    gf2_q_poly_add(q_val, q_f, q_u_i_by_delta);

    if (0 != gf2_q_poly_cmp(q_val, q_tilde)) {
        return PERK_FAILURE;
    }
    return PERK_SUCCESS;
}

// Alg 4.24
uint8_t sig_perk_verify_check_pkp(const sig_perk_f_poly_t *a, const perk_vole_data_t q[], const gf2_q_poly delta,
                                  const uint16_t t[PERK_PARAM_N], const sig_perk_public_key_t *pk,
                                  const ch2_t ch2_bar) {
    gf2_q_poly q_beta[PERK_PARAM_N][2 * PERK_PARAM_L_ROW - 6] = {0};
    gf2_q_poly q_z[PERK_PARAM_N][PERK_PARAM_N] = {0};
    gf2_q_poly q_col_check[PERK_PARAM_N] = {0};
    gf2_q_poly q_x_prime[PERK_PARAM_N] = {0};
    gf2_q_poly q_y[PERK_PARAM_M] = {0};
    gf2_q_poly alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M] = {0};
    gf2_q_poly q_elt_vect_check[PERK_PARAM_N][PERK_PARAM_C] = {0};
    gf2_q_poly q_f = {0};

    sig_perk_verify_vole_permutation(q_beta, q_z, q_col_check, delta, t, q);
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        v_check_elementary_vector(q_elt_vect_check[i], delta, (const gf2_q_poly *)q_beta[i]);
    }
    sig_perk_verify_compute_x_prime(q_x_prime, q_z, pk);
    sig_perk_verify_compute_y(q_y, q_x_prime, pk);
    // Generate alpha
    sig_perk_generate_alpha_array(alpha, ch2_bar);
    sig_perk_verify_merge_polynomials(q_f, q_col_check, q_elt_vect_check, q_y, alpha);
    uint8_t b = sig_perk_verify_check_zero(delta, q_f, a, q);
    return b;
}
