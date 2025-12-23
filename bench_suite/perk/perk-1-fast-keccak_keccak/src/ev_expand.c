/**
 * @file ev_expand.c
 * @brief Expansion of the elementary vectors
 */

#include "ev_expand.h"
#include <string.h>
#include "data_structures.h"

static void sig_perk_gf2_by_gf2_q_poly(gf2_q_poly o, const gf2_elt e1, const gf2_q_poly e2) {
    for (int i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        o[i] = e1 * e2[i];
    }
}

static inline void copy_gf2_q_poly(gf2_q_poly o, const gf2_q_poly e1) {
    for (int i = 0; i < PERK_TOWER_FIELD_EXT; i++) {
        o[i] = e1[i];
    }
}

static inline void add_deg2(sig_perk_share_z_t *sum, sig_perk_share_z_t *add1, sig_perk_share_z_t *add2) {
    gf2_q_poly_add(sum->v[0], add1->v[0], add2->v[0]);
    gf2_q_poly_add(sum->v[1], add1->v[1], add2->v[1]);
    sum->u = add1->u ^ add2->u;
}

#define IMPLEMENT_MUL                                   \
    gf2_q_poly_mulmod(prod->v[0], fact1->v, fact2->v);  \
                                                        \
    gf2_q_poly v1;                                      \
    gf2_q_poly v2;                                      \
    sig_perk_gf2_by_gf2_q_poly(v1, fact1->u, fact2->v); \
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v); \
    gf2_q_poly_add(prod->v[1], v1, v2);                 \
                                                        \
    prod->u = fact1->u * fact2->u;

// (u1*x+v1) * (u2*x+v2) = u1*u2*x^2 + (u1*v2 + v1*u2)*x + v1*v2
static inline void mul_deg1_by_deg1(sig_perk_share_z_t *prod, sig_perk_beta_prime_t *fact1,
                                    sig_perk_beta_prime_t *fact2) {
    IMPLEMENT_MUL
}

// (u1*x+v1) * (u2*x+v2) = u1*u2*x^2 + (u1*v2 + v1*u2)*x + v1*v2
static inline void mul_deg1_by_deg1_to_check_ev(sig_perk_check_ev_t *prod, sig_perk_beta_prime_t *fact1,
                                                sig_perk_beta_prime_t *fact2) {
    IMPLEMENT_MUL
}

// (u1*x+v11)*x + u2*x^2+v21*x+v22
static inline void add_vole_by_x_with_deg2(sig_perk_share_z_t *sum, sig_perk_beta_prime_t *add1,
                                           sig_perk_share_z_t *add2) {
    copy_gf2_q_poly(sum->v[0], add2->v[0]);
    gf2_q_poly_add(sum->v[1], add1->v, add2->v[1]);
    sum->u = add1->u ^ add2->u;
}

/*  [V00 V01 V02 (X + V00 + V01 + V02)] * [V10 V11 V12 (X + V10 + V11 + V12)] * [V20 V21 V22 (X + V20 + V21 + V22)]

 0    V00 * V10
 1    V00 * V11
 2    V00 * V12
 3    V00 * (X + V10 + V11 + V12) = (V00 * X) + (V00 * V10) + (V00 * V11) + (V00 * V12)

 4    V01 * V10
 5    V01 * V11
 6    V01 * V12
 7    V01 * (X + V10 + V11 + V12) = (V01 * X) + (V01 * V10) + (V01 * V11) + (V01 * V12)

 8    V02 * V10
 9    V02 * V11
10    V02 * V12
11    V02 * (X + V10 + V11 + V12) = (V02 * X) + (V02 * V10) + (V02 * V11) + (V02 * V12)

12    (X + V00 + V01 + V02) * V10 = (V10 * X) + (V00 * V10) + (V01 * V10) + (V02 * V10)
13    (X + V00 + V01 + V02) * V11 = (V11 * X) + (V00 * V11) + (V01 * V11) + (V02 * V11)
14    (X + V00 + V01 + V02) * V12 = (V12 * X) + (V00 * V12) + (V01 * V12) + (V02 * V12)
15    (X + V00 + V01 + V02) * (X + V10 + V11 + V12) = (  X * X) + (V10 * X) + (V11 * X) + (V12 * X) +
                                                    (V00 * X) + (V00 * V10) + (V00 * V11) + (V00 * V12)
                                                    (V01 * X) + (V01 * V10) + (V01 * V11) + (V01 * V12)
                                                    (V02 * X) + (V02 * V10) + (V02 * V11) + (V02 * V12) =

                                                    (  X * X) + (V10 * X) + (V11 * X) + (V12 * X) +
                                                    (V00 * V14) + (V01 * V14) + (V02 * V14)


*/

// order as in specs
/*  [V00 V01 V02 (X + V00 + V01 + V02)] * [V10 V11 V12 (X + V10 + V11 + V12)] * [V20 V21 V22 (X + V20 + V21 + V22)]

 0    V00 * V10
 1    V01 * V10
 2    V02 * V10
 3    (X + V00 + V01 + V02) * V10 = (V10 * X) + (V00 * V10) + (V01 * V10) + (V02 * V10)

 4    V00 * V11
 5    V01 * V11
 6    V02 * V11
 7    (X + V00 + V01 + V02) * V11 = (V11 * X) + (V00 * V11) + (V01 * V11) + (V02 * V11)

 8    V00 * V12
 9    V01 * V12
10    V02 * V12
11    (X + V00 + V01 + V02) * V12 = (V12 * X) + (V00 * V12) + (V01 * V12) + (V02 * V12)

12    V00 * (X + V10 + V11 + V12) = (V00 * X) + (V00 * V10) + (V00 * V11) + (V00 * V12)
13    V01 * (X + V10 + V11 + V12) = (V01 * X) + (V01 * V10) + (V01 * V11) + (V01 * V12)
14    V02 * (X + V10 + V11 + V12) = (V02 * X) + (V02 * V10) + (V02 * V11) + (V02 * V12)
15    (X + V00 + V01 + V02) * (X + V10 + V11 + V12) = (  X * X) + (V10 * X) + (V11 * X) + (V12 * X) +
                                                    (V00 * X) + (V00 * V10) + (V00 * V11) + (V00 * V12)
                                                    (V01 * X) + (V01 * V10) + (V01 * V11) + (V01 * V12)
                                                    (V02 * X) + (V02 * V10) + (V02 * V11) + (V02 * V12) =

                                                    (  X * X) + (V10 * X) + (V11 * X) + (V12 * X) +
                                                    (V00 * V14) + (V01 * V14) + (V02 * V14)


*/

#define PERK_SHARES_DEG2 (4 * 4)

static inline void add_deg1(sig_perk_beta_prime_t *sum, sig_perk_beta_prime_t *add1, sig_perk_beta_prime_t *add2) {
    gf2_q_poly_add(sum->v, add1->v, add2->v);
    sum->u = add1->u ^ add2->u;
}

#ifdef TEST_EXPAND_DEG2
#include <stdlib.h>
__attribute__((unused)) static inline void perk_ev_expand_deg2_ref(
    sig_perk_share_z_t shares_deg2[PERK_SHARES_DEG2],
    sig_perk_beta_prime_t voles_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]) {
    //
    sig_perk_beta_prime_t X = {1, {0}};

    sig_perk_beta_prime_t V13;
    add_deg1(&V13, &X, &voles_row[1][0]);
    add_deg1(&V13, &V13, &voles_row[1][1]);
    add_deg1(&V13, &V13, &voles_row[1][2]);

    sig_perk_beta_prime_t V03;
    add_deg1(&V03, &X, &voles_row[0][0]);
    add_deg1(&V03, &V03, &voles_row[0][1]);
    add_deg1(&V03, &V03, &voles_row[0][2]);

    mul_deg1_by_deg1(&shares_deg2[0], &voles_row[1][0], &voles_row[0][0]);
    mul_deg1_by_deg1(&shares_deg2[1], &voles_row[1][0], &voles_row[0][1]);
    mul_deg1_by_deg1(&shares_deg2[2], &voles_row[1][0], &voles_row[0][2]);
    mul_deg1_by_deg1(&shares_deg2[3], &voles_row[1][0], &V03);

    mul_deg1_by_deg1(&shares_deg2[4], &voles_row[1][1], &voles_row[0][0]);
    mul_deg1_by_deg1(&shares_deg2[5], &voles_row[1][1], &voles_row[0][1]);
    mul_deg1_by_deg1(&shares_deg2[6], &voles_row[1][1], &voles_row[0][2]);
    mul_deg1_by_deg1(&shares_deg2[7], &voles_row[1][1], &V03);

    mul_deg1_by_deg1(&shares_deg2[8], &voles_row[1][2], &voles_row[0][0]);
    mul_deg1_by_deg1(&shares_deg2[9], &voles_row[1][2], &voles_row[0][1]);
    mul_deg1_by_deg1(&shares_deg2[10], &voles_row[1][2], &voles_row[0][2]);
    mul_deg1_by_deg1(&shares_deg2[11], &voles_row[1][2], &V03);

    mul_deg1_by_deg1(&shares_deg2[12], &V13, &voles_row[0][0]);
    mul_deg1_by_deg1(&shares_deg2[13], &V13, &voles_row[0][1]);
    mul_deg1_by_deg1(&shares_deg2[14], &V13, &voles_row[0][2]);
    mul_deg1_by_deg1(&shares_deg2[15], &V13, &V03);
}
#endif

static inline void perk_ev_expand_deg2(sig_perk_share_z_t shares_deg2[PERK_SHARES_DEG2],
                                       sig_perk_beta_prime_t voles_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]) {
    //
    for (unsigned i = 0; i < 3; i++) {
        unsigned j = i * 4;
        mul_deg1_by_deg1(&shares_deg2[j + 0], &voles_row[1][i], &voles_row[0][0]);
        mul_deg1_by_deg1(&shares_deg2[j + 1], &voles_row[1][i], &voles_row[0][1]);
        mul_deg1_by_deg1(&shares_deg2[j + 2], &voles_row[1][i], &voles_row[0][2]);

        add_vole_by_x_with_deg2(&shares_deg2[j + 3], &voles_row[1][i], &shares_deg2[j + 0]);
        add_deg2(&shares_deg2[j + 3], &shares_deg2[j + 3], &shares_deg2[j + 1]);
        add_deg2(&shares_deg2[j + 3], &shares_deg2[j + 3], &shares_deg2[j + 2]);
    }
    for (unsigned i = 0; i < 3; i++) {
        unsigned j = 3 * 4;
        add_vole_by_x_with_deg2(&shares_deg2[j + i], &voles_row[0][i], &shares_deg2[i + 0]);
        add_deg2(&shares_deg2[j + i], &shares_deg2[j + i], &shares_deg2[i + 4]);
        add_deg2(&shares_deg2[j + i], &shares_deg2[j + i], &shares_deg2[i + 8]);
    }
    add_deg2(&shares_deg2[15], &shares_deg2[12], &shares_deg2[13]);
    add_deg2(&shares_deg2[15], &shares_deg2[15], &shares_deg2[14]);
    add_vole_by_x_with_deg2(&shares_deg2[15], &voles_row[1][0], &shares_deg2[15]);
    add_vole_by_x_with_deg2(&shares_deg2[15], &voles_row[1][1], &shares_deg2[15]);
    add_vole_by_x_with_deg2(&shares_deg2[15], &voles_row[1][2], &shares_deg2[15]);
    shares_deg2[15].u ^= 1;
}

// (u1*x^2 + v11*x + v10) * (u2*x + v20) = u1*u2*x^3 + (u1*v20 + v11*u2)*x^2 + (v11*v20 + v10*u2)*x + v10*v20
static inline void mul_deg2_by_deg1(sig_perk_share_z_t *prod, sig_perk_share_z_t *fact1, sig_perk_beta_prime_t *fact2) {
    //
    gf2_q_poly_mulmod(prod->v[0], fact1->v[0], fact2->v);

    gf2_q_poly v1;
    gf2_q_poly v2;
    gf2_q_poly_mulmod(v1, fact1->v[1], fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[0]);
    gf2_q_poly_add(prod->v[1], v1, v2);

    sig_perk_gf2_by_gf2_q_poly(v1, fact1->u, fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[1]);
    gf2_q_poly_add(prod->v[2], v1, v2);

    prod->u = fact1->u * fact2->u;
}

// (u1*x^3 + v12*x^2 + v11*x + v10) * (u2*x + v20) =
// u1*u2*x^4 + v12*u2*x^3 + v11*u2*x^2 + v10*u2*x  +  u1*v20*x^3 + v12*v20*x^2 + v11*v20*x + v10*v20 =
// u1*u2*x^4 + (v12*u2 + u1*v20)*x^3 + (v11*u2 + v12*v20)*x^2 + (v10*u2 + v11*v20)*x + v10*v20
#if (PERK_PARAM_N > 64)
static inline void mul_deg3_by_deg1(sig_perk_share_z_t *prod, sig_perk_share_z_t *fact1, sig_perk_beta_prime_t *fact2) {
    sig_perk_share_z_t tmp = {0};
    memcpy(&tmp, fact1, sizeof(tmp));
    fact1 = &tmp;
    // v10*v20
    gf2_q_poly_mulmod(prod->v[0], fact1->v[0], fact2->v);
    // (v10*u2 + v11*v20)
    gf2_q_poly v1;
    gf2_q_poly v2;
    gf2_q_poly_mulmod(v1, fact1->v[1], fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[0]);
    gf2_q_poly_add(prod->v[1], v1, v2);
    // (v11*u2 + v12*v20)
    gf2_q_poly_mulmod(v1, fact1->v[2], fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[1]);
    gf2_q_poly_add(prod->v[2], v1, v2);
    // (v12*u2 + u1*v20)
    sig_perk_gf2_by_gf2_q_poly(v1, fact1->u, fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[2]);
    gf2_q_poly_add(prod->v[3], v1, v2);
    // u1*u2
    prod->u = fact1->u * fact2->u;
}
static inline void double_mul_deg3_by_deg1(sig_perk_share_z_t *prod0, sig_perk_share_z_t *prod1,
                                           sig_perk_share_z_t *fact1, sig_perk_beta_prime_t *fact2, gf2_elt u2_1) {
    sig_perk_share_z_t tmp = {0};
    memcpy(&tmp, fact1, sizeof(tmp));
    fact1 = &tmp;
    // v10*v20
    gf2_q_poly_mulmod(prod0->v[0], fact1->v[0], fact2->v);
    memcpy(prod1->v[0], prod0->v[0], sizeof(prod1->v[0]));
    // (v10*u2 + v11*v20)
    gf2_q_poly v1;
    gf2_q_poly v2;
    gf2_q_poly_mulmod(v1, fact1->v[1], fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[0]);
    gf2_q_poly_add(prod0->v[1], v1, v2);
    sig_perk_gf2_by_gf2_q_poly(v2, u2_1, fact1->v[0]);
    gf2_q_poly_add(prod1->v[1], v1, v2);
    // (v11*u2 + v12*v20)
    gf2_q_poly_mulmod(v1, fact1->v[2], fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[1]);
    gf2_q_poly_add(prod0->v[2], v1, v2);
    sig_perk_gf2_by_gf2_q_poly(v2, u2_1, fact1->v[1]);
    gf2_q_poly_add(prod1->v[2], v1, v2);
    // (v12*u2 + u1*v20)
    sig_perk_gf2_by_gf2_q_poly(v1, fact1->u, fact2->v);
    sig_perk_gf2_by_gf2_q_poly(v2, fact2->u, fact1->v[2]);
    gf2_q_poly_add(prod0->v[3], v1, v2);
    sig_perk_gf2_by_gf2_q_poly(v2, u2_1, fact1->v[2]);
    gf2_q_poly_add(prod1->v[3], v1, v2);
    // u1*u2
    prod0->u = fact1->u * fact2->u;
    prod1->u = fact1->u * u2_1;
}
#endif

void sig_perk_tensor_product_to_ev(sig_perk_share_z_t shares_row[PERK_PARAM_N],
                                   sig_perk_beta_prime_t voles_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]) {
    //
    sig_perk_share_z_t shares_deg2[PERK_SHARES_DEG2] = {0};
    perk_ev_expand_deg2(shares_deg2, voles_row);

    for (unsigned i = 0; i < 16; i++) {
        mul_deg2_by_deg1(&shares_row[i + (0 * 16)], &shares_deg2[i], &voles_row[2][0]);

        mul_deg2_by_deg1(&shares_row[i + (1 * 16)], &shares_deg2[i], &voles_row[2][1]);

        mul_deg2_by_deg1(&shares_row[i + (2 * 16)], &shares_deg2[i], &voles_row[2][2]);

        // implement: mul_deg2_by_deg1(&shares_row[i + (3 * 16)], &shares_deg2[i], &V23);
        // given V23 = (1*x + 0) + voles_row[2][0] + voles_row[2][1] + voles_row[2][2]
        shares_row[i + (3 * 16)].u =
            shares_row[i + (0 * 16)].u ^ shares_row[i + (1 * 16)].u ^ shares_row[i + (2 * 16)].u ^ shares_deg2[i].u;
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[0], shares_row[i + (0 * 16)].v[0], shares_row[i + (1 * 16)].v[0]);
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[0], shares_row[i + (3 * 16)].v[0], shares_row[i + (2 * 16)].v[0]);

        gf2_q_poly_add(shares_row[i + (3 * 16)].v[1], shares_row[i + (0 * 16)].v[1], shares_row[i + (1 * 16)].v[1]);
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[1], shares_row[i + (3 * 16)].v[1], shares_row[i + (2 * 16)].v[1]);
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[1], shares_row[i + (3 * 16)].v[1], shares_deg2[i].v[0]);

        gf2_q_poly_add(shares_row[i + (3 * 16)].v[2], shares_row[i + (0 * 16)].v[2], shares_row[i + (1 * 16)].v[2]);
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[2], shares_row[i + (3 * 16)].v[2], shares_row[i + (2 * 16)].v[2]);
        gf2_q_poly_add(shares_row[i + (3 * 16)].v[2], shares_row[i + (3 * 16)].v[2], shares_deg2[i].v[1]);
    }

#if (PERK_PARAM_N > 64)
    // voles_row[3][0] and voles_row[3][0] have the same v, we leverage this
    int i;
    for (i = (PERK_PARAM_N - 1); i >= 64; i--) {
        // mul_deg3_by_deg1(&shares_row[i], &shares_row[i % 64], &voles_row[3][1]);
        // mul_deg3_by_deg1(&shares_row[i - 64], &shares_row[i % 64], &voles_row[3][0]);
        double_mul_deg3_by_deg1(&shares_row[i], &shares_row[i - 64], &shares_row[i % 64], &voles_row[3][1],
                                voles_row[3][0].u);
    }
    for (; i > ((PERK_PARAM_N - 1) - 64); i--) {
        mul_deg3_by_deg1(&shares_row[i], &shares_row[i % 64], &voles_row[3][0]);
    }
#endif
}

void check_elementary_vector(sig_perk_check_ev_t elt_vec_check[PERK_PARAM_C],
                             sig_perk_beta_prime_t beta_prime_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1]) {
    //
    sig_perk_beta_prime_t X = {1, {0}};
    sig_perk_beta_prime_t beta_prime_row_i__3 = {0};

    for (unsigned i = 0; i < 3; i++) {
        // build the 4th element
        add_deg1(&beta_prime_row_i__3, &X, &beta_prime_row[i][0]);
        add_deg1(&beta_prime_row_i__3, &beta_prime_row_i__3, &beta_prime_row[i][1]);
        add_deg1(&beta_prime_row_i__3, &beta_prime_row_i__3, &beta_prime_row[i][2]);
        // chck elementary block
        mul_deg1_by_deg1_to_check_ev(&elt_vec_check[i * 2 + 0], &beta_prime_row[i][0], &beta_prime_row[i][1]);
        mul_deg1_by_deg1_to_check_ev(&elt_vec_check[i * 2 + 1], &beta_prime_row[i][2], &beta_prime_row_i__3);
    }
#if (PERK_PARAM_N > 64)
    mul_deg1_by_deg1_to_check_ev(&elt_vec_check[6], &beta_prime_row[3][0], &beta_prime_row[3][1]);
#endif
}
