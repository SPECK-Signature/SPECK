/**
 * @file voles.c
 * @brief voles related functions
 */

#include "voles.h"
#include "ggm_tree.h"
#include "parameters.h"

#if (PRG_EXPAND_SEED_IMPL == aes)
#include "vole_prg2_aes.h"
#elif (PRG_EXPAND_SEED_IMPL == xkcp)
#include "vole_prg2_keccak.h"
#else
#error "Invalid PRG mode"
#endif

#if FINAL_COMMITMENT_MODE == xkcp4x
#include "symmetric_times4.h"
#endif

#define SIG_PERK_UNIVERSAL_HASH_B_BITS 16
#define SIG_PERK_UNIVERSAL_HASH_B      (SIG_PERK_UNIVERSAL_HASH_B_BITS / 8)

unsigned sig_perk_convert_to_vole(perk_vole_data_t u, perk_vole_data_t v[], const unsigned subtree, const salt_t salt,
                                  const ggm_tree_t ggm_tree) {
    //
    unsigned const k = ggm_tree_subtree_k(subtree);
    unsigned const N = 1 << k;
    unsigned const mu = (subtree < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);

    perk_vole_data_t r[1 << (PERK_PARAM_KAPPA1 - 1U)] = {0};

    // v0 := · · · := vd−1 := 0
    // u and v are zeroed by the caller
    for (unsigned i = 0; i < N / 4; i++) {
        perk_vole_data_t u2 = {0};

        const uint8_t* seed4[] = {
            ggm_tree[ggm_tree_leaf_index(subtree, 4 * i + 0)], ggm_tree[ggm_tree_leaf_index(subtree, 4 * i + 1)],
            ggm_tree[ggm_tree_leaf_index(subtree, 4 * i + 2)], ggm_tree[ggm_tree_leaf_index(subtree, 4 * i + 3)]};
        uint8_t* out[] = {r[2 * i + 0], u, r[2 * i + 1], u2};  // use u as tmp

        sig_perk_vole_PRG2_times4(out, salt, seed4);

        xor_vole(v[0], v[0], u);
        xor_vole(r[2 * i], r[2 * i], u);
        xor_vole(v[0], v[0], u2);
        xor_vole(r[2 * i + 1], r[2 * i + 1], u2);
    }

    for (unsigned j = 1; j < k; j++) {
        unsigned const Ndiv2tothejplus1 = (N / (1 << (j + 1)));
        for (unsigned i = 0; i < Ndiv2tothejplus1; i++) {
            //
            xor_vole(v[j], v[j], r[2 * i + 1]);
            xor_vole(r[i], r[2 * i], r[2 * i + 1]);
        }
    }
    for (unsigned j = k; j < mu; j++) {
        memset(v[j], 0, sizeof(perk_vole_data_t));
    }

    memcpy(u, r[0], sizeof(perk_vole_data_t));
    return mu;
}

// alg. 3.16
void sig_perk_vole_commit(cmt_t h_com, perk_vole_data_t c[PERK_PARAM_TAU - 1], perk_vole_data_t u,
                          perk_vole_data_t v[PERK_PARAM_RHO], const salt_t salt, ggm_tree_t const ggm_tree,
                          const cmt_array_t cmt_array) {
    perk_vole_data_t u_i = {0};
    unsigned idx = 0;
    sig_perk_hash_state_t h_com_state = {0};

#if FINAL_COMMITMENT_MODE == xkcp4x

    const uint8_t* cmt_array4[] = {(uint8_t*)(cmt_array + (PARAM_L / 4) * 0), (uint8_t*)(cmt_array + (PARAM_L / 4) * 1),
                                   (uint8_t*)(cmt_array + (PARAM_L / 4) * 2),
                                   (uint8_t*)(cmt_array + (PARAM_L / 4) * 3)};

    cmt_t dst[4] = {0};
    uint8_t* dst4[] = {dst[0], dst[1], dst[2], dst[3]};

    // Hash x4
    sig_perk_hash_times4_state_t state_COMx4 = {0};
    sig_perk_hash_times4_init(&state_COMx4, salt, NULL, NULL);
    sig_perk_hash_times4_update(&state_COMx4, cmt_array4, (sizeof(cmt_t) * (PARAM_L / 4)));
    sig_perk_hash_times4_final(&state_COMx4, dst4, Com2_1);

    // Merge the 4 blocks
    sig_perk_hash_init(&h_com_state, salt, NULL, NULL);
    sig_perk_hash_update(&h_com_state, (uint8_t*)dst, sizeof(cmt_t) * 4);
    sig_perk_hash_final(&h_com_state, h_com, Com2_0);

#elif FINAL_COMMITMENT_MODE == xkcp1x

    // alg. 3.11 lines 5 to 9
    sig_perk_hash_init(&h_com_state, salt, NULL, NULL);
    for (unsigned e = 0; e < PERK_PARAM_TAU; e++) {
        unsigned const N = 1 << ggm_tree_subtree_k(e);

        for (unsigned i = 0; i < N; i++) {
            sig_perk_hash_update(&h_com_state, cmt_array[ggm_tree_cmt_index(e, i)], sizeof(cmt_t));
        }
    }
    sig_perk_hash_final(&h_com_state, h_com, Com2);
#else
#error "Invalid final commitment mode"
#endif

    for (unsigned i = 0; i < PERK_PARAM_TAU; i++) {
        idx += sig_perk_convert_to_vole(u_i, v + idx, i, salt, ggm_tree);
        if (i == 0) {
            memcpy(u, u_i, sizeof(perk_vole_data_t));
        } else {
            xor_vole(c[i - 1], u, u_i);
        }
    }
}

/**
 * @brief permutes the seeds, zeroise r_0_0 and convert to voles
 *        implement Alg. 3.18 lines 2 and 3
 *
 * @param u
 * @param v
 * @param subtree
 * @param delta_e
 * @param salt
 * @param ggm_tree
 * @return unsigned number of computed elements in v array
 */
#if 1
unsigned sig_perk_permute_and_convert_to_vole(perk_vole_data_t v[], const unsigned subtree, uint32_t delta_e,
                                              const salt_t salt, const ggm_tree_t ggm_tree) {
    //
    unsigned const k = ggm_tree_subtree_k(subtree);
    unsigned const N = 1 << k;
    unsigned const mu = (subtree < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);

    perk_vole_data_t r[1 << (PERK_PARAM_KAPPA1 - 1U)] = {0};
    perk_vole_data_t u;

    // v0 := · · · := vd−1 := 0
    memset(v, 0, sizeof(perk_vole_data_t) * k);
    memset(u, 0, sizeof(perk_vole_data_t));
    for (unsigned i = 0; i < N / 4; i++) {
        perk_vole_data_t u2 = {0};

        const uint8_t* seed4[] = {ggm_tree[ggm_tree_leaf_index(subtree, (4 * i + 0) ^ delta_e)],
                                  ggm_tree[ggm_tree_leaf_index(subtree, (4 * i + 1) ^ delta_e)],
                                  ggm_tree[ggm_tree_leaf_index(subtree, (4 * i + 2) ^ delta_e)],
                                  ggm_tree[ggm_tree_leaf_index(subtree, (4 * i + 3) ^ delta_e)]};
        uint8_t* out[] = {r[2 * i + 0], u, r[2 * i + 1], u2};  // use u as tmp

        sig_perk_vole_PRG2_times4(out, salt, seed4);

        if (i == 0) {
            memset(r[i], 0, sizeof(perk_vole_data_t));
        }

        xor_vole(v[0], v[0], u);
        xor_vole(r[2 * i], r[2 * i], u);
        xor_vole(v[0], v[0], u2);
        xor_vole(r[2 * i + 1], r[2 * i + 1], u2);
    }

    for (unsigned j = 1; j < k; j++) {
        unsigned const Ndiv2tothejplus1 = (N / (1 << (j + 1)));
        for (unsigned i = 0; i < Ndiv2tothejplus1; i++) {
            //
            xor_vole(v[j], v[j], r[2 * i + 1]);
            xor_vole(r[i], r[2 * i], r[2 * i + 1]);
        }
    }
    for (unsigned j = k; j < mu; j++) {
        memset(v[j], 0, sizeof(perk_vole_data_t));
    }

    return mu;
}
#else
unsigned sig_perk_permute_and_convert_to_vole(perk_vole_data_t v[], const unsigned subtree, uint32_t delta_e,
                                              const salt_t salt, const ggm_tree_t ggm_tree) {
    //
    //
    unsigned const k = ggm_tree_subtree_k(subtree);
    unsigned const N = 1 << k;
    unsigned const mu = (subtree < PERK_PARAM_TAU_PRIME ? PERK_PARAM_MU1 : PERK_PARAM_MU2);
    perk_vole_data_t u = {0};

    sig_perk_prg_state_t state = {0};

    // v0 := · · · := vd−1 := 0
    memset(v, 0, sizeof(perk_vole_data_t) * mu);
    memset(u, 0, sizeof(perk_vole_data_t));

    for (unsigned i = 0; i < N; i++) {
        perk_vole_data_t temp = {0};
        unsigned permuted_i = i ^ delta_e;
        if (i != 0) {
            sig_perk_prg_init(&state, salt, ggm_tree[ggm_tree_leaf_index(subtree, permuted_i)]);
            sig_perk_prg_final(&state, PRG2);
            sig_perk_prg(&state, temp, sizeof(perk_vole_data_t));
        }

        for (unsigned j = 0; j < mu; j++) {
            if ((i >> j) & 1U) {
                xor_vole(v[j], v[j], temp);
            }
        }
    }

    return mu;
}
#endif

// alg. 3.18
int vole_reconstuct(cmt_t h_com, perk_vole_data_t q_prime[PERK_PARAM_RHO], i_vect_t i_vect,
                    const node_seed_t pdecom[PERK_PARAM_T_OPEN], const cmt_t com_e_i[PERK_PARAM_TAU],
                    const salt_t salt) {
    //
    ggm_tree_t partial_ggm_tree = {0};
    cmt_array_t cmt_array = {0};
    sig_perk_hash_state_t h_com_state = {0};

    // alg 3.13 VC.reconstruct
    int ret = expand_partial_ggm_tree(partial_ggm_tree, salt, pdecom, i_vect);
    if (ret < 0) {
        return PERK_FAILURE;  // wrong i_vec
    }
    build_ggm_tree_leaf_cmt(cmt_array, salt, (const_ggm_tree_t)partial_ggm_tree);
    for (unsigned e = 0; e < PERK_PARAM_TAU; e++) {  // fix commitments for the hidden leaves
        memcpy(cmt_array[i_vect[e] - LEAVES_SEEDS_OFFSET], com_e_i[e], sizeof(cmt_t));
    }

#if FINAL_COMMITMENT_MODE == xkcp4x

    const uint8_t* cmt_array4[] = {(uint8_t*)(cmt_array + (PARAM_L / 4) * 0), (uint8_t*)(cmt_array + (PARAM_L / 4) * 1),
                                   (uint8_t*)(cmt_array + (PARAM_L / 4) * 2),
                                   (uint8_t*)(cmt_array + (PARAM_L / 4) * 3)};

    cmt_t dst[4] = {0};
    uint8_t* dst4[] = {dst[0], dst[1], dst[2], dst[3]};

    // Hash x4
    sig_perk_hash_times4_state_t state_COMx4 = {0};
    sig_perk_hash_times4_init(&state_COMx4, salt, NULL, NULL);
    sig_perk_hash_times4_update(&state_COMx4, cmt_array4, (sizeof(cmt_t) * (PARAM_L / 4)));
    sig_perk_hash_times4_final(&state_COMx4, dst4, Com2_1);

    // Merge the 4 blocks
    sig_perk_hash_init(&h_com_state, salt, NULL, NULL);
    sig_perk_hash_update(&h_com_state, (uint8_t*)dst, sizeof(cmt_t) * 4);
    sig_perk_hash_final(&h_com_state, h_com, Com2_0);

#elif FINAL_COMMITMENT_MODE == xkcp1x

    sig_perk_hash_init(&h_com_state, salt, NULL, NULL);
    for (unsigned e = 0; e < PERK_PARAM_TAU; e++) {
        unsigned const N = 1 << ggm_tree_subtree_k(e);

        for (unsigned i = 0; i < N; i++) {
            sig_perk_hash_update(&h_com_state, cmt_array[ggm_tree_cmt_index(e, i)], sizeof(cmt_t));
        }
    }
    sig_perk_hash_final(&h_com_state, h_com, Com2);
#else
#error "Invalid final commitment mode"
#endif

    // lines 2 to 8
    unsigned idx = 0;
    for (unsigned e = 0; e < PERK_PARAM_TAU; e++) {
        uint8_t e1;
        uint16_t delta_e;
        ggm_tree_subtree_and_leaf(&e1, &delta_e, i_vect[e]);
        if (e != e1) {
            return PERK_FAILURE;
        }
        idx +=
            sig_perk_permute_and_convert_to_vole(q_prime + idx, e, delta_e, salt, (const_ggm_tree_t)partial_ggm_tree);
    }
    return PERK_SUCCESS;
}

static void sig_perk_compute_h1(gf2_64_elt h1, uint8_t* t, uint8_t* x) {
    gf2_64_elt b_t = {0};
    sig_perk_gf2_64_from_bytes(b_t, t);

    unsigned int lambdaBytes = PERK_SECURITY_BITS / 8;
    const uint16_t length_lambda = (PERK_PARAM_L + PERK_PARAM_L_BAR + (PERK_SECURITY_BITS - 1)) / PERK_SECURITY_BITS;

    uint8_t tmp[32] = {0};  // max security bytes
    memcpy(tmp, x + (length_lambda - 1) * lambdaBytes,
           (PERK_PARAM_L + PERK_PARAM_L_BAR) % PERK_SECURITY_BITS == 0
               ? lambdaBytes
               : (PERK_PARAM_L + PERK_PARAM_L_BAR) % PERK_SECURITY_BITS / 8);

    memset(h1, 0, GF2_64_ELT_UINT8_SIZE);  // Set to zero

    gf2_64_elt running_t = {0};
    running_t[0] = 1;  // Set to one

    unsigned int i = 0;
    for (; i < lambdaBytes; i += 8) {
        gf2_64_elt tmp_elt = {0};
        sig_perk_gf2_64_from_bytes(tmp_elt, tmp + (lambdaBytes - i - 8));
        sig_perk_gf2_64_mul(tmp_elt, running_t, tmp_elt);
        sig_perk_gf2_64_add(h1, h1, tmp_elt);
        sig_perk_gf2_64_mul(running_t, running_t, b_t);
    }
    for (; i < length_lambda * lambdaBytes; i += 8) {
        gf2_64_elt tmp_elt = {0};
        sig_perk_gf2_64_from_bytes(tmp_elt, x + (length_lambda * lambdaBytes - i - 8));
        sig_perk_gf2_64_mul(tmp_elt, running_t, tmp_elt);
        sig_perk_gf2_64_add(h1, h1, tmp_elt);
        sig_perk_gf2_64_mul(running_t, running_t, b_t);
    }
}

void sig_perk_vole_hash(uint8_t* h, uint8_t* sd, uint8_t* x) {
    uint8_t* r0 = sd;
    uint8_t* r1 = sd + PERK_SECURITY_BYTES;
    uint8_t* r2 = sd + 2 * PERK_SECURITY_BYTES;
    uint8_t* r3 = sd + 3 * PERK_SECURITY_BYTES;
    uint8_t* s = sd + 4 * PERK_SECURITY_BYTES;
    uint8_t* t = sd + 5 * PERK_SECURITY_BYTES;
    uint8_t* x1 = x;
    uint8_t* x0 = x + (PERK_PARAM_L_VHM / 8);

    // compute length_lambda = l'/lambda, where l' = lambda*floor( (l+(d-1)rho)/lambda )
    const uint16_t length_lambda =
        (PERK_PARAM_L + PERK_PARAM_L_BAR + (PERK_SECURITY_BITS - 1)) / PERK_SECURITY_BITS;  // l'/lambda

    uint8_t tmp[GF2_LAMBDA_ELT_UINT8_SIZE] = {0};
    memcpy(tmp, x0 + (length_lambda - 1) * GF2_LAMBDA_ELT_UINT8_SIZE,
           (PERK_PARAM_L + PERK_SECURITY_BITS) % PERK_SECURITY_BITS == 0
               ? GF2_LAMBDA_ELT_UINT8_SIZE
               : ((PERK_PARAM_L + PERK_SECURITY_BITS) % PERK_SECURITY_BITS) / 8);
    gf2_lambda_elt h0 = {0};
    sig_perk_gf2_lambda_from_bytes(h0, tmp);

    gf2_lambda_elt b_s = {0};
    sig_perk_gf2_lambda_from_bytes(b_s, s);

    gf2_lambda_elt running_s = {0};
    sig_perk_gf2_lambda_set(running_s, b_s);
    for (unsigned int i = 1; i != length_lambda; ++i) {
        gf2_lambda_elt temp_elt;
        sig_perk_gf2_lambda_from_bytes(temp_elt, x0 + (length_lambda - 1 - i) * PERK_SECURITY_BYTES);
        sig_perk_gf2_lambda_mul(temp_elt, running_s, temp_elt);
        sig_perk_gf2_lambda_add(h0, h0, temp_elt);
        sig_perk_gf2_lambda_mul(running_s, running_s, b_s);
    }
    gf2_64_elt h1 = {0};
    sig_perk_compute_h1(h1, t, x0);
    gf2_lambda_elt h1p = {0};
    sig_perk_gf2_lambda_from_gf2_64(h1p, h1);

    gf2_lambda_elt r0_t = {0};
    sig_perk_gf2_lambda_from_bytes(r0_t, r0);
    sig_perk_gf2_lambda_mul(r0_t, r0_t, h0);
    gf2_lambda_elt r1_t = {0};
    sig_perk_gf2_lambda_from_bytes(r1_t, r1);
    sig_perk_gf2_lambda_mul(r1_t, r1_t, h1p);
    gf2_lambda_elt h2 = {0};
    sig_perk_gf2_lambda_add(h2, r0_t, r1_t);

    gf2_lambda_elt r2_t = {0};
    sig_perk_gf2_lambda_from_bytes(r2_t, r2);
    sig_perk_gf2_lambda_mul(r2_t, r2_t, h0);
    gf2_lambda_elt r3_t = {0};
    sig_perk_gf2_lambda_from_bytes(r3_t, r3);
    sig_perk_gf2_lambda_mul(r3_t, r3_t, h1p);
    gf2_lambda_elt h3 = {0};
    sig_perk_gf2_lambda_add(h3, r2_t, r3_t);

    sig_perk_gf2_lambda_to_bytes(h, h2);
    sig_perk_gf2_lambda_to_bytes(tmp, h3);
    memcpy(h + PERK_SECURITY_BYTES, tmp, SIG_PERK_UNIVERSAL_HASH_B);
    // xor arrays
    for (size_t i = 0; i < PERK_VOLE_HASH_BYTES; i++) {
        h[i] = x1[i] ^ h[i];
    }
}
