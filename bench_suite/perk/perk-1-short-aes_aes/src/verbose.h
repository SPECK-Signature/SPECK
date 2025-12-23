
/**
 * @file verbose.h
 * @brief Header file verbose.c
 */

#ifndef SIG_PERK_VERBOSE_H
#define SIG_PERK_VERBOSE_H

#include <stdint.h>
#include "data_structures.h"

/**
 * @brief Print a string
 *
 * @param [in] var a string containing the characters to print
 */
void sig_perk_verbose_print_string(const char *var);

/**
 * @brief Print in hexadecimal format a given number of bytes
 *
 * @param [in] var a string containing the name of the variable to be printed
 * @param [in] input a string containing the data to be printed
 * @param [in] size an integer that is the number of bytes to be printed
 */
void sig_perk_verbose_print_uint8_t_array(const char *var, const uint8_t *input, uint16_t size);

/**
 * @brief Print in decimal format a given number of bytes
 *
 * @param [in] var a string containing the name of the variable to be printed
 * @param [in] input a string containing the data to be printed
 * @param [in] size an integer that is the number of bytes to be printed
 */
void sig_perk_verbose_print_uint16_t_array(const char *var, const uint16_t *input, uint16_t size);

/**
 * @brief Print a permutation vector in decimal.
 *
 * @param[in] var   Label printed before the values (e.g., variable name).
 * @param[in] perm  Pointer to the first element of the permutation array.
 * @param[in] n     Number of elements to print.
 */
void sig_perk_verbose_print_perm(const char *var, const uint8_t *perm, uint16_t n);

/**
 * @brief Print a matrix of type ::sig_perk_mat_t in hexadecimal format.
 *
 * @param[in] var  A string label to identify the printed variable.
 * @param[in] mat  The matrix of type ::sig_perk_mat_t to be printed.
 */
void sig_perk_verbose_print_sig_perk_mat_t(const char *var, const sig_perk_mat_t mat);

/**
 * @brief Print all coefficients of a PERK sig_perk_f_poly_t in hex.
 *
 * Prints the contents of @p a->u and each @p a->v[j] as 4-digit
 * lowercase hex words. Intended for debugging only.
 *
 * @param a Polynomial to print (must not be NULL).
 */
void sig_perk_verbose_print_f_poly_t(const sig_perk_f_poly_t *a);

/**
 * @brief Print a 64-bit counter in hexadecimal.
 *
 * @param ctr Counter value.
 */
void sig_perk_verbose_print_ctr(uint64_t ctr);

/**
 * @brief Print an array of node seeds in hex, one per line.
 *
 * @param pdecom Array of seeds.
 */
void sig_perk_verbose_print_pdecom_seeds(const node_seed_t pdecom[PERK_PARAM_T_OPEN]);

/**
 * @brief Print the contents of an i_vect_t in decimal.
 *
 * @param v The vector to print.
 */
void sig_perk_verbose_print_i_vect(const i_vect_t v);

/**
 * @brief Print an array of commitments in hex, one per line.
 *
 * @param com_e_i Array of commitments to print.
 */
void sig_perk_verbose_print_commitments(const cmt_t com_e_i[PERK_PARAM_TAU]);

/**
 * @brief Print a message and a signature
 *
 * @param [in] m a string containing a message
 * @param [in] mlen an integer that is the size of a message
 * @param [in] signature a string containing a signature
 */
void sig_perk_verbose_print_signature_raw(const uint8_t *m, uint64_t mlen, const uint8_t *signature);

#ifdef VERBOSE
#define SIG_PERK_VERBOSE_PRINT_string(var)                      sig_perk_verbose_print_string(var)
#define SIG_PERK_VERBOSE_PRINT_uint8_t_array(var, input, size)  sig_perk_verbose_print_uint8_t_array(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_uint16_t_array(var, input, size) sig_perk_verbose_print_uint16_t_array(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_perm(var, input, size)           sig_perk_verbose_print_perm(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_sig_perk_mat_t(var, input)       sig_perk_verbose_print_sig_perk_mat_t(var, input)
#define SIG_PERK_VERBOSE_PRINT_f_poly_t_struct(a)               sig_perk_verbose_print_f_poly_t(a)
#define SIG_PERK_VERBOSE_PRINT_counter(ctr)                     sig_perk_verbose_print_ctr(ctr)
#define SIG_PERK_VERBOSE_PRINT_pdecom_seeds(pdecom)             sig_perk_verbose_print_pdecom_seeds(pdecom)
#define SIG_PERK_VERBOSE_PRINT_i_vect_t(i_vect)                 sig_perk_verbose_print_i_vect(i_vect)
#define SIG_PERK_VERBOSE_PRINT_com_e_i(com_e_i)                 sig_perk_verbose_print_commitments(com_e_i)
#define SIG_PERK_VERBOSE_PRINT_signature_raw(m, mlen, signature) \
    sig_perk_verbose_print_signature_raw(m, mlen, signature)
#else
#define SIG_PERK_VERBOSE_PRINT_string(var)
#define SIG_PERK_VERBOSE_PRINT_uint8_t_array(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_uint16_t_array(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_perm(var, input, size)
#define SIG_PERK_VERBOSE_PRINT_sig_perk_mat_t(var, input)
#define SIG_PERK_VERBOSE_PRINT_f_poly_t_struct(a)
#define SIG_PERK_VERBOSE_PRINT_counter(ctr)
#define SIG_PERK_VERBOSE_PRINT_pdecom_seeds(pdecom)
#define SIG_PERK_VERBOSE_PRINT_i_vect_t(i_vect)
#define SIG_PERK_VERBOSE_PRINT_com_e_i(com_e_i)
#define SIG_PERK_VERBOSE_PRINT_signature_raw(m, mlen, signature)
#endif  // VERBOSE

#endif  // SIG_PERK_VERBOSE_H
