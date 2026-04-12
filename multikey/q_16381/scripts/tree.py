from math import comb,log2,ceil,floor

def l_child(a):
    return 2*a + 1

def r_child(a):
    return 2*a + 2


def clog2(a):
    return max(int(ceil(log2(a))), 1)

def hamming_weight_of_value(x):
    hw = 0
    while x > 0:
        hw += x & 1
        x = x >> 1
    return hw

def print_tree_defines(npl,off,lpl,start_indices,cons_leaves,nodes_to_store):
    c_array_npl = repr(npl).replace("[","{").replace("]","}")
    c_array_off = repr(off).replace("[","{").replace("]","}")
    c_array_lpl = repr(lpl).replace("[","{").replace("]","}")
    c_array_start_indices = repr(start_indices).replace("[","{").replace("]","}")
    c_array_cons_leaves = repr(cons_leaves).replace("[","{").replace("]","}")
    print(f"#define TREE_OFFSETS {c_array_off}")
    print(f"#define TREE_NODES_PER_LEVEL {c_array_npl}")
    print(f"#define TREE_LEAVES_PER_LEVEL {c_array_lpl}")
    print(f"#define TREE_SUBROOTS {subroots}")
    print(f"#define TREE_LEAVES_START_INDICES {c_array_start_indices}")
    print(f"#define TREE_CONSECUTIVE_LEAVES {c_array_cons_leaves}")
    print(f'#define TREE_NODES_TO_STORE {nodes_to_store}')


def worst_case_tree_nodes(num_rounds_t,seeds_to_hide):
    num_set_bits_w = num_rounds_t-seeds_to_hide
    weight_t_1 = hamming_weight_of_value(num_rounds_t) - 1
    return floor(seeds_to_hide*log2(num_rounds_t/seeds_to_hide) + weight_t_1)

# Compute the offsets for the truncated trees required to move between two levels
def tree_offsets_and_nodes(T):

    # Full trees on the left half, so we can already count (i.e. subtract) these values as well as the root node
    missing_nodes_per_level = [2**(i-1) for i in range(1, clog2(T)+1)]
    missing_nodes_per_level.insert(0,0)

    remaining_leaves = T - 2**(clog2(T)-1)
    level = 1

    # Starting from the first level, we construct the tree in a way that the left
    # subtree is always a full binary tree.
    while(remaining_leaves > 0):
        depth = 0
        stree_found = False
        while not stree_found:
            if (remaining_leaves <= 2**depth):
                for i in range(depth, 0, -1):
                    missing_nodes_per_level[level+i] -= 2**(i-1)
                remaining_leaves -= (2**clog2(remaining_leaves)) // 2

                # Subtract root and increase level for next iteration
                missing_nodes_per_level[level] -= 1
                level += 1
                stree_found = True
            else:
                depth += 1
            
    # The offsets are the missing nodes per level subtracted by the missing nodes of all previous levels, as this
    # is already included 
    offsets = [missing_nodes_per_level[i] for i in range(len(missing_nodes_per_level))]
    for i in range(clog2(T), -1, -1):
        for j in range(i):
            offsets[i] -= offsets[j]

    nodes_per_level = [2**i - missing_nodes_per_level[i] for i in range(clog2(T)+1)]
    return offsets, nodes_per_level

# Compute the number of subtrees and corresponding start indices of the leaf nodes within
# the full tree.
def tree_leaves(T, offsets):
    leaves = [0]*T
    leaves_per_level = [0]*(clog2(T)+1)
    start_index_per_level = [0]*(clog2(T)+1)
    ctr = 0

    remaining_leaves = T
    depth = 0
    level = 0
    root_node = 0
    left_child = l_child(root_node) - offsets[level+depth]
    
    while (remaining_leaves > 0):
        depth = 1
        subtree_found = False
        while not subtree_found:
            if (remaining_leaves <= 2**depth):
                for i in range(2**clog2(remaining_leaves)//2):
                    leaves[ctr] = root_node if remaining_leaves==1 else left_child+i
                    if (remaining_leaves==1):
                        leaves_per_level[level] += 1
                        start_index_per_level[level] = root_node if start_index_per_level[level] == 0 else start_index_per_level[level]
                    else:
                        leaves_per_level[level+depth] += 1
                        start_index_per_level[level+depth] = left_child if start_index_per_level[level+depth] == 0 else start_index_per_level[level+depth]
                    ctr += 1
                root_node = r_child(root_node) - offsets[level]
                left_child = l_child(root_node) - offsets[level]
                level += 1
                remaining_leaves -= 2**clog2(remaining_leaves)//2
                subtree_found = True
            else:
                left_child = l_child(left_child) - offsets[level+depth]
                depth += 1

    # Now create array with start idx and number of leaves by removing zeros
    cons_leaves = [i for i in leaves_per_level if i != 0]
    start_index_per_level = [i for i in start_index_per_level if i != 0]

    return leaves_per_level, len(cons_leaves), start_index_per_level[::-1], cons_leaves[::-1]

t = 40
w = 19
opt = 'BALANCED'

off, npl = tree_offsets_and_nodes(t)
lpl, subroots, start_idx, cons_leaves = tree_leaves(t, off)
if opt == "SPEED":
    nodes_to_store = w
else:
    nodes_to_store = worst_case_tree_nodes(t,t-w)
print_tree_defines(npl,off,lpl,start_idx,cons_leaves,nodes_to_store)
