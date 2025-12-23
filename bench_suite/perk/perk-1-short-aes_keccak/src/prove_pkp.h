#ifndef SIG_PERK_PROVE_PKP_H
#define SIG_PERK_PROVE_PKP_H

#include "data_structures.h"
#include "parameters.h"
#include "permutation.h"
#include "voles.h"

void sig_perk_vole_permutation(uint16_t t[PERK_PARAM_N],
                               sig_perk_beta_prime_t beta_array[PERK_PARAM_N][PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                               sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N],
                               sig_perk_check_t col_check_array[PERK_PARAM_N], const sig_perk_private_key_t *sk,
                               const perk_vole_data_t u, const perk_vole_data_t v[]);
void sig_perk_compute_masked_secret(uint16_t *t, sig_perk_sk_encodings_t *sk_encodings, const uint8_t pos,
                                    const uint8_t pos_index, const perk_vole_data_t u);

uint16_t sig_perk_extract_bits(const uint8_t *array, size_t bit_offset);

void sig_perk_embed_witness(sig_perk_beta_prime_t beta_prime_row[PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                            uint8_t w_prime[PERK_PARAM_D], unsigned uk_index, const perk_vole_data_t v[PERK_PARAM_RHO]);

void sig_perk_check_pkp(sig_perk_f_poly_t *a, sig_perk_check_t col_check_array[PERK_PARAM_N],
                        sig_perk_beta_prime_t beta_array[PERK_PARAM_N][PERK_PARAM_D][PERK_PARAM_BASIS - 1],
                        sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N], const sig_perk_public_key_t *pk,
                        const perk_vole_data_t u, const perk_vole_data_t v[], const ch2_t ch2);

void sig_perk_print_share_array(sig_perk_share_t *share_array, size_t size);

void sig_perk_generate_alpha_array(gf2_q_poly *alpha, const ch2_t ch2);

int open_vector_commitments(ch3_t ch3, uint64_t *ctr, node_seed_t s_seeds[PERK_PARAM_T_OPEN], i_vect_t i_vect,
                            const ggm_tree_t ggm_tree, ch2_t ch2, sig_perk_f_poly_t *a);

void challenge_decode(i_vect_t i_vect, const ch3_t ch3);

void sig_perk_compute_x_prime(sig_perk_share_t x_prime[PERK_PARAM_N],
                              sig_perk_share_z_t z_array[PERK_PARAM_N][PERK_PARAM_N], const sig_perk_public_key_t *pk);

void sig_perk_compute_y(sig_perk_share_t y[PERK_PARAM_M], sig_perk_share_t x_prime[PERK_PARAM_N],
                        const sig_perk_public_key_t *pk);

void sig_perk_merge_polys(sig_perk_f_poly_t *f_w, sig_perk_check_t col_check_array[PERK_PARAM_N],
                          sig_perk_check_ev_t elt_vect_check[PERK_PARAM_N * PERK_PARAM_C],
                          sig_perk_share_t y[PERK_PARAM_M],
                          gf2_q_poly alpha[(PERK_PARAM_N + PERK_PARAM_C * PERK_PARAM_N) + PERK_PARAM_M]);
void sig_perk_check_zero(sig_perk_f_poly_t *a, sig_perk_f_poly_t *f_w, const perk_vole_data_t u,
                         const perk_vole_data_t v[]);

void sig_perk_print_struct_share_z_t(sig_perk_share_z_t z);
void sig_perk_print_struct_share_t(sig_perk_share_t s);
void sig_perk_print_struct_check_t(sig_perk_check_t c);
void sig_perk_print_struct_f_poly_t(sig_perk_f_poly_t f);

#endif  // SIG_PERK_PROVE_PKP_H
