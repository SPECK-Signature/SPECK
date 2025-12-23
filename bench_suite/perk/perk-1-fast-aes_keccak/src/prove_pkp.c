#include "prove_pkp.h"
#include "ev_expand.h"
#include "gf_poly_arithmetic.h"
#include "ggm_tree.h"
#include "keygen.h"
#include "parameters.h"
#include "parsing.h"
#include "randombytes.h"
#include "signature.h"
#include "symmetric.h"
#include "symmetric_times4.h"

uint16_t sig_perk_extract_bits(const uint8_t *array, size_t bit_offset) {
    uint32_t result = 0;
    size_t byte_offset = bit_offset / 8;
    size_t bit_in_byte = bit_offset % 8;

    for (size_t i = 0; i < (bit_in_byte + PERK_PARAM_L_ROW + 7) / 8; i++) {
        result |= (uint32_t)array[byte_offset + i] << (i * 8);
    }

    result >>= bit_in_byte;
    result &= (1ULL << PERK_PARAM_L_ROW) - 1;

    return (uint16_t)result;
}

// Alg 3.21 EncodeNum()
static inline void sig_perk_encode_num(sig_perk_sk_encodings_t *sk_encodings, const uint8_t pos) {
#if (PERK_CONFIG_PARAM_SEC_LEVEL == 1)
    sk_encodings->enc_pos_array[2] = pos >> 4;
    sk_encodings->enc_pos_array[1] = (pos - (sk_encodings->enc_pos_array[2] << 4)) >> 2;
    sk_encodings->enc_pos_array[0] =
        pos - (sk_encodings->enc_pos_array[2] << 4) - (sk_encodings->enc_pos_array[1] << 2);
#endif

#if (PERK_CONFIG_PARAM_SEC_LEVEL == 3 || PERK_CONFIG_PARAM_SEC_LEVEL == 5)
    sk_encodings->enc_pos_array[3] = pos >> 6;
    uint8_t pos_tmp = pos - (sk_encodings->enc_pos_array[3] << 6);
    sk_encodings->enc_pos_array[2] = pos_tmp >> 4;
    sk_encodings->enc_pos_array[1] = (pos_tmp - (sk_encodings->enc_pos_array[2] << 4)) >> 2;
    sk_encodings->enc_pos_array[0] =
        pos_tmp - (sk_encodings->enc_pos_array[2] << 4) - (sk_encodings->enc_pos_array[1] << 2);
#endif
}

// Alg 3.23 EncPosArrayToWitness()
static inline void sig_perk_enc_pos_array_to_witness(sig_perk_sk_encodings_t *sk_encodings) {
    for (unsigned i = 0; i < PERK_PARAM_D; i++) {
        sk_encodings->w_prime[i] = 1 << sk_encodings->enc_pos_array[i];
    }
}

// Alg 3.26 PosToWitness()
static inline void sig_perk_pos_to_witness(sig_perk_sk_encodings_t *sk_encodings, const uint8_t pos) {
    sig_perk_encode_num(sk_encodings, pos);
    sig_perk_enc_pos_array_to_witness(sk_encodings);
}

// Alg 3.24 CompWit()
static inline void sig_perk_comp_wit(sig_perk_sk_encodings_t *sk_encodings) {
    uint8_t mask = 0x07;
    // Step 2
    sk_encodings->w = sk_encodings->w_prime[0] & mask;
    sk_encodings->w |= (sk_encodings->w_prime[1] & mask) << 3;
    sk_encodings->w |= (sk_encodings->w_prime[2] & mask) << 6;
#if (PERK_CONFIG_PARAM_SEC_LEVEL == 3 || PERK_CONFIG_PARAM_SEC_LEVEL == 5)
    sk_encodings->w |= (sk_encodings->w_prime[3] & 0x01) << 9;
#endif
}

void sig_perk_compute_masked_secret(uint16_t *t, sig_perk_sk_encodings_t *sk_encodings, const uint8_t pos,
                                    const uint8_t pos_index, const perk_vole_data_t u) {
    // Step 1
    sig_perk_pos_to_witness(sk_encodings, pos);
    // Step 2
    sig_perk_comp_wit(sk_encodings);
    // Step 3
    size_t bit_offset = pos_index * PERK_PARAM_L_ROW;
    uint16_t u_bits = sig_perk_extract_bits(u + (PERK_PARAM_L_VHM / 8), bit_offset);
    *t = sk_encodings->w ^ u_bits;
}

void sig_perk_embed_witness(sig_perk_beta_prime_t beta_prime_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                            uint8_t w_prime[PERK_PARAM_D], unsigned uk_index,
                            const perk_vole_data_t v[PERK_PARAM_RHO]) {
    //
    for (unsigned i = 0; i < 3; i++) {
        // alg. 3.27 P.EmbedWitnessBlock
        for (unsigned j = 0; j < 3; j++) {
            beta_prime_row[i][j].u = (w_prime[i] >> j) & 1U;
            sig_perk_v_to_tower_field(beta_prime_row[i][j].v, uk_index + PERK_PARAM_L_VHM, v);
            uk_index++;
        }
        // skip step 5:  β′_i,3(X) := w′_i,3X + v0 + v1 + v2
        // will be reconstructed later
    }

#if (PERK_PARAM_D == 4)
    for (unsigned j = 0; j < 2; j++) {
        beta_prime_row[3][j].u = (w_prime[3] >> j) & 1U;
        sig_perk_v_to_tower_field(beta_prime_row[3][j].v, uk_index + PERK_PARAM_L_VHM,
                                  v);  // this use the same vole correlation see lines 9 and 10 in specs
    }
#endif
}

static void sig_perk_vole_elementary_vect(sig_perk_share_z_t shares_row[PERK_PARAM_N],
                                          sig_perk_beta_prime_t beta_prime_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                                          uint16_t *t, const uint8_t pos, const uint8_t pos_index,
                                          const perk_vole_data_t u, const perk_vole_data_t v[]) {
    sig_perk_sk_encodings_t sk_encodings = {0};
    sig_perk_compute_masked_secret(t, &sk_encodings, pos, pos_index, u);
    sig_perk_embed_witness(beta_prime_row, sk_encodings.w_prime, pos_index * PERK_PARAM_L_ROW, v);
    sig_perk_tensor_product_to_ev(shares_row, beta_prime_row);
}

void sig_perk_vole_permutation(uint16_t t[PERK_PARAM_N],
                               sig_perk_beta_prime_t beta_array[PERK_PARAM_N][PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                               sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N],
                               sig_perk_check_t col_check_array[PERK_PARAM_N], const sig_perk_private_key_t *sk,
                               const perk_vole_data_t u, const perk_vole_data_t v[]) {
    // Steps 1, 2 and 3 in Alg 3.32 P.VOLE-Permutation
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        sig_perk_vole_elementary_vect(z_array[i], beta_array[i], &t[i], sk->p[i], i, u, v);
    }

    // Steps 4 to 7 in Alg 3.32 P.VOLE-Permutation
    for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
        for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
            col_check_array[j].u ^= z_array[j][i].u;
            for (unsigned k = 0; k < PERK_PARAM_D; ++k) {
                gf2_q_poly_add(col_check_array[j].v[k], col_check_array[j].v[k], z_array[j][i].v[k]);
            }
        }
        col_check_array[j].u ^= 1;  // Step 6
    }
}

static inline void sig_perk_scal_mul_share1(sig_perk_share_t *a, sig_perk_share_z_t b, gf2_q_elt c) {
    // a->u = b.u * c;
    if (b.u) {
        a->u = c;
    }
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_scal_mul(a->v[i], b.v[i], c);
    }
}

static inline void sig_perk_scal_mul_share2(sig_perk_share_t *a, sig_perk_share_t b, gf2_q_elt c) {
    sig_perk_gf2_q_mul(&a->u, b.u, c);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_scal_mul(a->v[i], b.v[i], c);
    }
}

static inline void sig_perk_add_shares(sig_perk_share_t *a, sig_perk_share_t b, sig_perk_share_t c) {
    sig_perk_gf2_q_add(&a->u, b.u, c.u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_add(a->v[i], b.v[i], c.v[i]);
    }
}

void sig_perk_compute_x_prime(sig_perk_share_t x_prime[PERK_PARAM_N],
                              sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N], const sig_perk_public_key_t *pk) {
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
            sig_perk_share_t tmp = {0};
            sig_perk_scal_mul_share1(&tmp, z_array[j][i], pk->x[j]);
            sig_perk_add_shares(&x_prime[i], x_prime[i], tmp);
        }
    }
}

void sig_perk_compute_y(sig_perk_share_t y[PERK_PARAM_M], sig_perk_share_t x_prime[PERK_PARAM_N],
                        const sig_perk_public_key_t *pk) {
    for (unsigned i = 0; i < PERK_PARAM_M; ++i) {
        for (unsigned j = 0; j < PERK_PARAM_N; ++j) {
            sig_perk_share_t tmp = {0};
            sig_perk_scal_mul_share2(&tmp, x_prime[j], pk->H[i][j]);
            sig_perk_add_shares(&y[i], y[i], tmp);
        }
    }
}

// _Static_assert(sizeof(ch2_t) == sizeof(salt_t), "ch2_t has different size than salt_t");
// raise compile error if sizeof(ch2_t) != sizeof(salt_t)
// adapted from "https://stackoverflow.com/questions/4079243/how-can-i-use-sizeof-in-a-preprocessor-macro"
typedef int assert_sizeof_test[1 - 2 * !!(sizeof(ch2_t) != sizeof(salt_t))];

void sig_perk_generate_alpha_array(gf2_q_poly *alpha, const ch2_t ch2) {
    uint16_t nb_coefs = 0;

    sig_perk_prg_state_t state_H4 = {0};
    sig_perk_prg_init(&state_H4, ch2, NULL);
    sig_perk_prg_final(&state_H4, H4);

    uint64_t
        rnd_buff[(((PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M) * PERK_TOWER_FIELD_EXT * PERK_PARAM_Q +
                  63) /
                 64] = {0};

    sig_perk_prg(&state_H4, (uint8_t *)rnd_buff, sizeof(rnd_buff));

    nb_coefs = (PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M;
    int pos = 0, buff_index = 0;

    for (unsigned i = 0; i < nb_coefs; ++i) {
        for (unsigned j = 0; j < PERK_TOWER_FIELD_EXT; ++j) {
            alpha[i][j] = read_11bit_in_64bytearray(rnd_buff, pos, buff_index);
            pos += PERK_PARAM_Q;
            if (pos > 63) {
                buff_index++;
                pos -= 64;
            }
        }
    }
}

static inline void sig_perk_f_poly_scal_mul1(sig_perk_f_poly_t *a, sig_perk_check_t b, gf2_q_poly alpha_i) {
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        a->u[i] = b.u * alpha_i[i];
    }
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_mulmod(a->v[i], b.v[i], alpha_i);
    }
}

static inline void sig_perk_f_poly_scal_mul2(sig_perk_f_poly_t *a, sig_perk_share_t b, gf2_q_poly alpha_i) {
    gf2_q_poly_scal_mul(a->u, alpha_i, b.u);

    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_mulmod(a->v[i], b.v[i], alpha_i);
    }
}

static inline void sig_perk_f_poly_add(sig_perk_f_poly_t *a, sig_perk_f_poly_t *b, sig_perk_f_poly_t *c) {
    gf2_q_poly_add(a->u, b->u, c->u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        gf2_q_poly_add(a->v[i], b->v[i], c->v[i]);
    }
}

static inline void sig_perk_mul_check_ev_by_alpha(sig_perk_check_ev_by_alpha_t *a, sig_perk_check_ev_t *check_ev,
                                                  gf2_q_poly alpha_i) {
    for (unsigned i = 0; i < PERK_TOWER_FIELD_EXT; ++i) {
        a->u[i] = check_ev->u * alpha_i[i];
    }
    gf2_q_poly_mulmod(a->v[0], check_ev->v[0], alpha_i);
    gf2_q_poly_mulmod(a->v[1], check_ev->v[1], alpha_i);
}

static inline void sig_perk_check_ev_by_x_and_add(sig_perk_f_poly_t *a, sig_perk_f_poly_t *f_poly,
                                                  sig_perk_check_ev_by_alpha_t *b) {
    gf2_q_poly_add(a->u, f_poly->u, b->u);
    gf2_q_poly_add(a->v[PERK_PARAM_D - 1], f_poly->v[PERK_PARAM_D - 1], b->v[1]);
    gf2_q_poly_add(a->v[PERK_PARAM_D - 2], f_poly->v[PERK_PARAM_D - 2], b->v[0]);
}

void sig_perk_merge_polys(sig_perk_f_poly_t *f_w, sig_perk_check_t col_check_array[PERK_PARAM_N],
                          sig_perk_check_ev_t elt_vect_check[PERK_PARAM_N * PERK_PARAM_C],
                          sig_perk_share_t y[PERK_PARAM_M],
                          gf2_q_poly alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M]) {
    // Merge ColCheck
    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        sig_perk_f_poly_t tmp = {0};
        sig_perk_f_poly_scal_mul1(&tmp, col_check_array[i], alpha[i]);
        sig_perk_f_poly_add(f_w, f_w, &tmp);
    }
    // Merge ElemVecCheck
    for (unsigned i = 0; i < (PERK_PARAM_C * PERK_PARAM_N); ++i) {
        sig_perk_check_ev_by_alpha_t tmp = {0};
        sig_perk_mul_check_ev_by_alpha(&tmp, &elt_vect_check[i], alpha[PERK_PARAM_N + i]);
        sig_perk_check_ev_by_x_and_add(f_w, f_w, &tmp);
    }
    // Merge y
    for (unsigned i = 0; i < PERK_PARAM_M; ++i) {
        sig_perk_f_poly_t tmp = {0};
        sig_perk_f_poly_scal_mul2(&tmp, y[i], alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + i]);
        sig_perk_f_poly_add(f_w, f_w, &tmp);
    }
}

void sig_perk_check_zero(sig_perk_f_poly_t *a, sig_perk_f_poly_t *f_w, const perk_vole_data_t u,
                         const perk_vole_data_t v[]) {
    sig_perk_f_poly_t f_mask = {0};
    gf2_q_poly fs_i[PERK_PARAM_D - 1][2] = {0};
    unsigned u_idx = PERK_PARAM_L_PRIME;
    unsigned v_idx = PERK_PARAM_L_PRIME;

    for (unsigned i = 0; i < (PERK_PARAM_D - 1); ++i) {
        sig_perk_u_to_tower_field(fs_i[i][1], u_idx, u);
        u_idx += PERK_PARAM_RHO;
        sig_perk_check_zero_v_to_tower_field(fs_i[i][0], v_idx, v);
        v_idx += PERK_PARAM_RHO;
    }

    memcpy(f_mask.v[0], fs_i[0][0], sizeof(gf2_q_poly));
#if (PERK_PARAM_D == 3)
    gf2_q_poly_add(f_mask.v[1], fs_i[1][0], fs_i[0][1]);
#endif
#if (PERK_PARAM_D == 4)
    gf2_q_poly_add(f_mask.v[1], fs_i[1][0], fs_i[0][1]);
    gf2_q_poly_add(f_mask.v[2], fs_i[1][1], fs_i[2][0]);
#endif
    memcpy(f_mask.v[PERK_PARAM_D - 1], fs_i[PERK_PARAM_D - 2][1], sizeof(gf2_q_poly));
    sig_perk_f_poly_add(a, f_w, &f_mask);
}

void sig_perk_check_pkp(sig_perk_f_poly_t *a, sig_perk_check_t col_check_array[PERK_PARAM_N],
                        sig_perk_beta_prime_t beta_array[PERK_PARAM_N][PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                        sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N], const sig_perk_public_key_t *pk,
                        const perk_vole_data_t u, const perk_vole_data_t v[], const ch2_t ch2) {
    sig_perk_share_t x_prime[PERK_PARAM_N] = {0};
    sig_perk_share_t y[PERK_PARAM_M] = {0};
    gf2_q_poly alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M] = {0};
    sig_perk_check_ev_t elt_vect_check[PERK_PARAM_N * PERK_PARAM_C] = {0};
    sig_perk_f_poly_t f_w = {0};

    for (unsigned i = 0; i < PERK_PARAM_N; ++i) {
        check_elementary_vector(elt_vect_check + (i * PERK_PARAM_C), beta_array[i]);
    }

    sig_perk_compute_x_prime(x_prime, z_array, pk);
    sig_perk_compute_y(y, x_prime, pk);
    // Generate alpha
    sig_perk_generate_alpha_array(alpha, ch2);
    // Merge polynomials
    sig_perk_merge_polys(&f_w, col_check_array, elt_vect_check, y, alpha);
    sig_perk_check_zero(a, &f_w, u, v);
}

void sig_perk_print_struct_f_poly_t(sig_perk_f_poly_t f) {
    printf("\n u = ");
    sig_perk_print_tower_field_element(f.u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        printf("\n v[%d] = ", i);
        sig_perk_print_tower_field_element(f.v[i]);
    }
    printf("\n\n\n");
}

void sig_perk_print_struct_share_z_t(sig_perk_share_z_t z) {
    printf("\n u = %d", z.u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        printf("\n v[%d] = ", i);
        sig_perk_print_tower_field_element(z.v[i]);
    }
    printf("\n");
}

void sig_perk_print_struct_share_t(sig_perk_share_t s) {
    printf("\nu = %" PRIx16 " ", s.u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        printf("\n v[%d] = ", i);
        sig_perk_print_tower_field_element(s.v[i]);
    }
    printf("\n");
}

void sig_perk_print_struct_check_t(sig_perk_check_t c) {
    printf("\n u = %d", c.u);
    for (unsigned i = 0; i < PERK_PARAM_D; ++i) {
        printf("\n v[%d] = ", i);
        sig_perk_print_tower_field_element(c.v[i]);
    }
    printf("\n");
}

void challenge_decode(i_vect_t i_vect, const ch3_t ch3) {
    // we parse the first (PERK_PARAM_KAPPA1 * PERK_PARAM_TAU1 + PERK_PARAM_KAPPA2 * PERK_PARAM_TAU2) of ch3
    unsigned i = 0;
    uint16_t pos = 0, index = 0;
    uint32_t val = 0;

    while (i < PERK_PARAM_TAU1) {
        val = sig_perk_read_n_bits_from_bytearray(ch3, &pos, &index, PERK_PARAM_KAPPA1);
        i_vect[i] = ggm_tree_leaf_index(i, val);
        i++;
    }
    while (i < PERK_PARAM_TAU) {
        val = sig_perk_read_n_bits_from_bytearray(ch3, &pos, &index, PERK_PARAM_KAPPA2);
        i_vect[i] = ggm_tree_leaf_index(i, val);
        i++;
    }
}

#define CHALL_DEC_BITS (PERK_PARAM_KAPPA1 * PERK_PARAM_TAU1 + PERK_PARAM_KAPPA2 * PERK_PARAM_TAU2)
#define CH3_W_MASK     ((1U << (unsigned)PERK_PARAM_W) - 1U)

int open_vector_commitments(ch3_t ch3, uint64_t *ctr, node_seed_t s_seeds[PERK_PARAM_T_OPEN], i_vect_t i_vect,
                            const ggm_tree_t ggm_tree, ch2_t ch2, sig_perk_f_poly_t *a) {
    *ctr = 0;

    const uint8_t *ax4[] = {(uint8_t *)a, (uint8_t *)a, (uint8_t *)a, (uint8_t *)a};

    sig_perk_prg_times4_state_t state4 = {0};
    sig_perk_prg_times4_init(&state4, ch2, NULL);
    sig_perk_prg_times4_update(&state4, ax4, sizeof(sig_perk_f_poly_t));

    uint64_t ctra[4] = {0, 1, 2, 3};
    const uint8_t *ctrx4[] = {(uint8_t *)&ctra[0], (uint8_t *)&ctra[1], (uint8_t *)&ctra[2], (uint8_t *)&ctra[3]};
    ch3_t ch3a[4] = {0};
    uint8_t *ch3x4[] = {ch3a[0], ch3a[1], ch3a[2], ch3a[3]};
    while (1) {
        // compute sig_perk_gen_third_challenge(ch3, ch2, a, ctr);

        sig_perk_prg_times4_state_t state_updated4 = state4;  // reuse initialized status
        sig_perk_prg_times4_update(&state_updated4, ctrx4, sizeof(uint64_t));
        sig_perk_prg_times4_final(&state_updated4, H2_3);
        sig_perk_prg_times4(&state_updated4, ch3x4, sizeof(ch3_t));

        for (unsigned i = 0; i < 4; i++) {
            uint32_t w_bits = 0xFFFFFFFF;
            uint16_t pos = (CHALL_DEC_BITS % 8), index = (CHALL_DEC_BITS / 8);
            w_bits = sig_perk_read_n_bits_from_bytearray(ch3a[i], &pos, &index, PERK_PARAM_W);
            if ((w_bits & CH3_W_MASK) == 0) {
                //
                challenge_decode(i_vect, ch3a[i]);
                int ret = open_ggm_tree(s_seeds, ggm_tree, i_vect);
                if (ret >= 0) {
                    *ctr = ctra[i];
                    memcpy(ch3, ch3a[i], sizeof(ch3_t));
                    // set to zero the last unused bits
                    uint8_t mask = (uint8_t)((1U << ((PERK_CHALL_3_BITS % 8U))) - 1U);
                    if (mask) {
                        ch3[PERK_CHALL_3_BYTES - 1] &= mask;
                    }
                    return PERK_SUCCESS;
                }
            }

            if (ctra[i] > PERK_PARAM_MAX_OPEN_RETRIES - 1) {
                *ctr = ctra[i];
                return PERK_FAILURE;
            }
            ctra[i] += 4;
        }
    }
    // we never reach this
}

void sig_perk_print_share_array(sig_perk_share_t *share_array, size_t size) {
    for (size_t i = 0; i < size; ++i) {
        printf("[");
        printf("%" PRIx16 " ", share_array[i].u);
        for (unsigned j = 0; j < PERK_PARAM_D; ++j) {
            sig_perk_print_tower_field_element(share_array[i].v[j]);
        }
        printf("] ");
    }
}
