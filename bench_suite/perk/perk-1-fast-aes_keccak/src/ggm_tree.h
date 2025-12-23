
/**
 * @file ggm_tree.h
 * @brief Header file for ggm_tree.c
 */

#ifndef GGM_TREE_H
#define GGM_TREE_H

#include <stdint.h>
#include "parameters.h"
#include "symmetric.h"

// number of leaves of the tree
#define PARAM_L1 (PERK_PARAM_TAU1 * (1 << PERK_PARAM_KAPPA1))
#define PARAM_L2 (PERK_PARAM_TAU2 * (1 << PERK_PARAM_KAPPA2))
#define PARAM_L  (PARAM_L1 + PARAM_L2)

// very conservative estimation of max number of nodes needed by the opening
#define Ceil_Log2_PARAM_L ((int)(sizeof(unsigned int) * 8) - __builtin_clz(PARAM_L - 1))
#define MAX_OPEN_NODES    (Ceil_Log2_PARAM_L * PERK_PARAM_TAU)

#define MASTER_TREE_SEED_OFFSET 0
#define LEAVES_SEEDS_OFFSET     (PARAM_L - 1)

#if (PARAM_L > 0xFFFF)
#error PARAM_L must fit in uint16_t
#endif

/**
 * @brief node_seed_t
 *
 *
 * This structure represent the node of the tree and
 * contains a seed of size PERK_SEED_BYTES bytes
 */
typedef uint8_t node_seed_t[PERK_SEED_BYTES];

/**
 * @brief An array of node_seed_t
 *
 * This structure contains an array of 2 * PARAM_L - 1 node_seed_t
 */
typedef node_seed_t ggm_tree_t[2 * PARAM_L - 1] __attribute__((aligned(32)));

/**
 * @brief type used to cast to a const ggm_tree
 */
typedef const uint8_t (*const const_ggm_tree_t)[sizeof(node_seed_t)];

/**
 * @brief array of tau indexes
 *
 * node indexes of the leaves to be hidden
 */
typedef uint32_t i_vect_t[PERK_PARAM_TAU];

/**
 * @brief expands the tree (nodes and leaves) from master seed
 *
 * @param[in,out] ggm_tree a ggm_tree_t to be expanded with nodes and leaves
 *                         ggm_tree[0] is the master seed
 *                         (ggm_tree + LEAVES_SEEDS_OFFSET) is the array of node_seed_t
 */
void expand_ggm_tree(ggm_tree_t ggm_tree, const salt_t salt);

/**
 * @brief returns the s_seeds needed to compute all leaves but the i_vect ones
 *        given ggm_tree_t and i_vect.
 *        s_seeds and s_indexes must be of MAX_OPEN_NODES size even if a smaller size is returned
 *
 * @param[out] s_seeds   array of seeds needed to rebuild the tree with the missing i_vect leaves
 * @param[in]  ggm_tree  a complete ggm_tree_t
 * @param[in]  i_vect    leaves to hide from the tree
 *
 * @return int -1 on error else the number of seeds in s_seeds
 */
int open_ggm_tree(node_seed_t s_seeds[PERK_PARAM_T_OPEN], const ggm_tree_t ggm_tree, const i_vect_t i_vect);

/**
 * @brief expands the partial tree (nodes and leaves missing the i_vect related ones)
 *        from s_seeds and s_indexes
 *
 * @param[out] partial_ggm_tree a ggm_tree_t to be expanded with nodes and leaves from the array s_seeds
 * @param[in]  s_seeds          array of seeds
 * @param[in]  salt
 * @param[in]  i_vect           leaves to hide from the tree
 *
 * @return int -1 on error
 */
int expand_partial_ggm_tree(ggm_tree_t partial_ggm_tree, const salt_t salt,
                            const node_seed_t s_seeds[PERK_PARAM_T_OPEN], const i_vect_t i_vect);

/**
 * @brief Commitment cmt_t
 *
 * This structure contains a commitment
 */
typedef uint8_t cmt_t[PERK_COMMITMENT_BYTES];

/**
 * @brief commitment array
 *
 * holds the commitments for the leaves of the tree
 */
typedef cmt_t cmt_array_t[PARAM_L];
typedef const uint8_t (*const const_cmt_array_t)[sizeof(cmt_t)];

#if (PERK_PARAM_KAPPA1 < PERK_PARAM_KAPPA2)
#error PERK_PARAM_KAPPA1 must be greater than PERK_PARAM_KAPPA2
#endif

/**
 * @brief returns the index of the leaf on the ggm_tree (forest) array given the subtree
 *        and the leaf on the subtree
 *
 * @param[in] subtree subtree to select
 * @param[in] leaf    leaf on the subtree
 *
 * @return uint32_t index of the leaf in the ggm_tree array
 */
static inline uint32_t ggm_tree_leaf_index(const unsigned subtree, const unsigned leaf) {
    uint32_t l_index = 0;

    if (leaf < (1 << PERK_PARAM_KAPPA2)) {
        l_index = (leaf * PERK_PARAM_TAU) + subtree;
    } else {
        l_index =
            ((1 << PERK_PARAM_KAPPA2) * PERK_PARAM_TAU) + (leaf - (1 << PERK_PARAM_KAPPA2)) * PERK_PARAM_TAU1 + subtree;
    }

    return l_index + LEAVES_SEEDS_OFFSET;
}

/**
 * @brief returns the subtree and the leaf on the ggm_tree (forest) array
 *        the leaf at node "index" belongs to
 *
 * @param[out] subtree the subtree the element at index "idx" belongs to
 * @param[out] leaf    the leaf the element at index "idx" belongs to
 * @param[in]  index   index index of the leaf in the ggm_tree array
 */
static inline void ggm_tree_subtree_and_leaf(uint8_t *subtree, uint16_t *leaf, uint32_t index) {
    index -= LEAVES_SEEDS_OFFSET;

    if (index < ((1 << PERK_PARAM_KAPPA2) * PERK_PARAM_TAU)) {
        *subtree = index % PERK_PARAM_TAU;
        *leaf = index / PERK_PARAM_TAU;
    } else {
        index -= ((1 << PERK_PARAM_KAPPA2) * PERK_PARAM_TAU);
        *subtree = index % PERK_PARAM_TAU1;
        *leaf = index / PERK_PARAM_TAU1 + (1 << PERK_PARAM_KAPPA2);
    }
}

/**
 * @brief returns the K (log2(N leaves)) of the subtree
 *
 * @param[in] subtree
 *
 * @return unsigned K of the subtree
 */
static inline unsigned ggm_tree_subtree_k(const unsigned subtree) {
    return (subtree < PERK_PARAM_TAU1 ? PERK_PARAM_KAPPA1 : PERK_PARAM_KAPPA2);
}

/**
 * @brief generates the commitments from the leaves of the tree.
 *        stores result in array of PARAM_L cmt_t elements
 *
 * @param cmt_array[out] output array of commitments
 * @param salt[in]       the salt
 * @param ggm_tree[in]   the tree
 */
void build_ggm_tree_leaf_cmt(cmt_array_t cmt_array, const salt_t salt, const ggm_tree_t ggm_tree);

/**
 * @brief returns the index of the commitment on the cmt_array array given the subtree
 *        and the leaf on the subtree
 *
 * @param[in] subtree subtree to select
 * @param[in] leaf    leaf on the subtree
 *
 * @return uint32_t index of the leaf in the ggm_tree array
 */
static inline uint32_t ggm_tree_cmt_index(const unsigned subtree, const unsigned leaf) {
    return ggm_tree_leaf_index(subtree, leaf) - LEAVES_SEEDS_OFFSET;
}

#endif
