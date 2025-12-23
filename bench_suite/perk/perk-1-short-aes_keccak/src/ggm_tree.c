
/**
 * @file ggm_tree.c
 * @brief Implementation of tree related functions
 */

#include "ggm_tree.h"
#include <string.h>
#include "KeccakHashtimes4.h"
#include "symmetric_times4.h"

#if (PRG_LEAF_COMMIT_IMPL == aes)
#include "leaf_commit_aes.h"
#elif (PRG_LEAF_COMMIT_IMPL == xkcp)
#include "leaf_commit_keccak.h"
#else
#error "Invalid commit mode"
#endif

#if (PRG_EXPAND_SEED_IMPL == aes)
#include "expand_seed_aes.h"
#elif (PRG_EXPAND_SEED_IMPL == xkcp)
#include "expand_seed_keccak.h"
#else
#error "Invalid PRG mode"
#endif

static inline unsigned child0(unsigned i) {
    return (i * 2) + 1;
}

static inline unsigned child1(unsigned i) {
    return (i * 2) + 2;
}

static inline unsigned sibling(unsigned i) {
    return i - 1 + (i & 1U ? 2 : 0);
}

static inline unsigned parent(unsigned i) {
    return (i - 1) / 2;
}

#include <stdio.h>
static unsigned insertSorted(uint32_t arr[], unsigned n, uint32_t key, unsigned capacity) {
    // Cannot insert more elements if n is already
    // more than or equal to capacity

    if (n >= capacity) {
        printf("\n\nCAPACITY Exceeded!!!! %u %u\n\n", n, capacity);
        return n;
    }

    int i;
    for (i = (int)n - 1; (i >= 0 && arr[i] > key); i--) {
        arr[i + 1] = arr[i];
    }

    arr[i + 1] = key;

    return (n + 1);
}

static int isInList(const uint32_t arr[], unsigned n, uint32_t x) {
    int l = 0;
    int r = (int)n - 1;
    // the loop will run till there are elements in the
    // subarray as l > r means that there are no elements to
    // consider in the given subarray
    while (l <= r) {
        // calculating mid point
        int m = l + (r - l) / 2;
        // Check if x is present at mid
        if (arr[m] == x) {
            return m;
        }
        // If x greater than ,, ignore left half
        if (arr[m] < x) {
            l = m + 1;
        }
        // If x is smaller than m, ignore right half
        else {
            r = m - 1;
        }
    }
    // if we reach here, then element was not present
    return -1;
}

static unsigned removeFromList(uint32_t arr[], unsigned n, unsigned pos) {
    if (pos >= n) {
        return n;
    }

    for (unsigned i = pos; i < n - 1; i++) {
        arr[i] = arr[i + 1];
    }

    return n - 1;
}

static int compute_s_indexes(uint32_t s_indexes[MAX_OPEN_NODES], const i_vect_t i_vect) {
    unsigned n = 0;
    for (unsigned i = 0; i < PERK_PARAM_TAU; i++) {
        uint32_t node = i_vect[i];
        while (node > 0) {
            int pos = isInList(s_indexes, n, node);

            if (pos >= 0) {
                n = removeFromList(s_indexes, n, (unsigned)pos);
                break;
            }

            unsigned n_prev = n;
            n = insertSorted(s_indexes, n, sibling(node), MAX_OPEN_NODES);
            if (n_prev == n) {
                return -1;
            }
            node = parent(node);
        }
    }
    return n;
}

void expand_ggm_tree(ggm_tree_t ggm_tree, const salt_t salt) {
    // Note that PARAM_L must be a multiple of 4
    unsigned i;

    for (i = 0; i < 3; i++) {
        ggm_expand_seed(ggm_tree + child0(i), salt, (uint16_t)i, ggm_tree[i]);
    }
    for (; i < (PARAM_L - 4); i += 4) {
        ggm_expand_seed_4x(ggm_tree + child0(i), salt, (uint16_t)i, (const node_seed_t *)(ggm_tree + i));
    }
}

int open_ggm_tree(node_seed_t s_seeds[PERK_PARAM_T_OPEN], const ggm_tree_t ggm_tree, const i_vect_t i_vect) {
    uint32_t s_indexes[MAX_OPEN_NODES] = {0};
    const int n = compute_s_indexes(s_indexes, i_vect);
    if ((n < 0) || (n > PERK_PARAM_T_OPEN)) {
        return -1;
    }

    for (int i = 0; i < n; i++) {
        memcpy(s_seeds[i], ggm_tree[s_indexes[i]], sizeof(node_seed_t));
    }
    // set other s_seeds to zero
    for (int i = n; i < PERK_PARAM_T_OPEN; i++) {
        memset(s_seeds[i], 0, sizeof(node_seed_t));
    }
    return n;
}

int expand_partial_ggm_tree(ggm_tree_t partial_ggm_tree, const salt_t salt,
                            const node_seed_t s_seeds[PERK_PARAM_T_OPEN], const i_vect_t i_vect) {
    unsigned k = 0;
    uint32_t s_indexes[MAX_OPEN_NODES] = {0};
    int ret = compute_s_indexes(s_indexes, i_vect);
    if ((ret < 0) || (ret > PERK_PARAM_T_OPEN)) {
        return -1;
    }
    const unsigned n = (unsigned)ret;
    // check the s_seeds beyond n to be zero
    for (int i = n; i < PERK_PARAM_T_OPEN; i++) {
        for (unsigned j = 0; j < sizeof(node_seed_t); j++) {
            if (s_seeds[i][j] != 0) {
                return -1;
            }
        }
    }

    uint32_t parent_node = parent(s_indexes[k]);
    uint8_t valid[PARAM_L + 1] = {0};

    unsigned i;
    for (i = 0; i < 3; i++) {
        if (i == parent_node) {
            memcpy(partial_ggm_tree + s_indexes[k], s_seeds[k], sizeof(node_seed_t));
            memset(partial_ggm_tree + sibling(s_indexes[k]), 0, sizeof(node_seed_t));
            if (i < (PARAM_L / 2)) {
                valid[s_indexes[k]] = 1;
            }
            k++;
            if (k < n) {
                parent_node = parent(s_indexes[k]);
            }
        } else {
            if (valid[i]) {
                ggm_expand_seed(partial_ggm_tree + child0(i), salt, (uint16_t)i, partial_ggm_tree[i]);
                if (i < (PARAM_L / 2)) {
                    valid[child0(i)] = 1;
                    valid[child1(i)] = 1;
                }
            } else {
                memset(partial_ggm_tree + child0(i), 0, 2 * sizeof(node_seed_t));
            }
        }
    }
    while (i < (PARAM_L - 4)) {
        ggm_expand_seed_4x(partial_ggm_tree + child0(i), salt, (uint16_t)i,
                           (const node_seed_t *)(partial_ggm_tree + i));
        for (unsigned j = 0; j < 4; j++, i++) {
            if (i == parent_node) {
                memcpy(partial_ggm_tree + s_indexes[k], s_seeds[k], sizeof(node_seed_t));
                memset(partial_ggm_tree + sibling(s_indexes[k]), 0, sizeof(node_seed_t));
                if (i < (PARAM_L / 2)) {
                    valid[s_indexes[k]] = 1;
                }
                k++;
                if (k < n) {
                    parent_node = parent(s_indexes[k]);
                }
            } else {
                if (valid[i]) {
                    if (i < (PARAM_L / 2)) {
                        valid[child0(i)] = 1;
                        valid[child1(i)] = 1;
                    }
                } else {
                    memset(partial_ggm_tree + child0(i), 0, 2 * sizeof(node_seed_t));
                }
            }
        }
    }
    return n;
}

// _Static_assert((PARAM_L % 4) == 0, "PARAM_L must be multiple of 4");
#if ((PARAM_L % 4) != 0)
#error "PARAM_L must be multiple of 4"
#endif

void build_ggm_tree_leaf_cmt(cmt_array_t cmt_array, const salt_t salt, const ggm_tree_t ggm_tree) {
    for (unsigned i = LEAVES_SEEDS_OFFSET; i < (LEAVES_SEEDS_OFFSET + PARAM_L); i += 4) {
        uint16_t n4[4] = {0};
        uint8_t tau4[4] = {0};

        for (unsigned k = 0; k < 4; k++) {
            ggm_tree_subtree_and_leaf(&tau4[k], &n4[k], i + k);
        }
        const uint8_t *seed_times4[] = {ggm_tree[i + 0], ggm_tree[i + 1], ggm_tree[i + 2], ggm_tree[i + 3]};
        uint8_t *cmt_times4[4] = {cmt_array[i - LEAVES_SEEDS_OFFSET + 0], cmt_array[i - LEAVES_SEEDS_OFFSET + 1],
                                  cmt_array[i - LEAVES_SEEDS_OFFSET + 2], cmt_array[i - LEAVES_SEEDS_OFFSET + 3]};

        ggm_leaf_commit_4x(cmt_times4, salt, tau4, n4, seed_times4);
    }
}
