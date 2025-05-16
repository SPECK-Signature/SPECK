from collections import Counter
from sage.all_cmdline import Combinations, Permutations, Arrangements
from math import comb
import random

def multiplicities(mset: list):
    sorted_mset = sorted(mset)
    cnt = [0 for _ in list(set(sorted_mset))]
    current_elem = sorted_mset[0]
    current_index = 0
    for i in range(0,len(sorted_mset)):
        if sorted_mset[i] != current_elem:
            current_index += 1
            current_elem = sorted_mset[i]
        cnt[current_index] += 1
    return cnt

def arrangements_mset_max_k(mset: list, k: int):
    cnt = multiplicities(mset)

    nrs = [0 for _ in range(k+1)]
    nrs[0]=1

    for n in range(0,len(cnt)):
        for l in range(k,0,-1):
            nr = 0
            bino = 1
            for i in range(min(cnt[n],l)+1):
                nr = nr + bino*nrs[l-i]
                bino = int(bino * (l-i)/(i+1))
            nrs[l] = nr
    return nrs

def arrangements_mset_k(mset, k):
    return arrangements_mset_max_k(mset,k)[k]

def permutations_of_combinations(mset,k):
    return sum([Permutations(comb).cardinality() for comb in Combinations(mset,k)])

def rec_calling_arrangements_mset_k(mset,k):
    mults = multiplicities(mset)
    arrs = recursive_arrangements_mset_k(mults,k)
    return arrs

def recursive_arrangements_mset_k(mults,k):
    if (k==0):
        return 1
    if (len(mults)==0):
        return 0

    arrs = 0
    for i in range(min(k,mults[len(mults)-1])+1):
        arrs += recursive_arrangements_mset_k(mults[:len(mults)-1], k-i)*binom_matrix[k][i]
    return arrs

def calc_binomials(k: int):
    binom_matrix=[]
    for x in range(0,k+1):
        binom = []
        for y in range(0,k+1):
            binom.append(comb(x,y))
        binom_matrix.append(binom)
    return binom_matrix

def arrangements_mult_max_k(cnt: list, k: int):
    nrs = [0 for _ in range(k+1)]
    nrs[0]=1

    for n in range(0,len(cnt)):
        for l in range(k,0,-1):
            nr = 0
            bino = 1
            for i in range(min(cnt[n],l)+1):
                nr = nr + bino*nrs[l-i]
                bino = int(bino * (l-i)/(i+1))
            nrs[l] = nr
    return nrs

def prob_xi_more_than_k(no,q,k):
    prob = 0
    for i in range(k,no+1):
        prob += binomial(no,i)*((1/q)^i)*((1-(1/q))^(no-i))
    return prob

def compute_pkp_cost(mset,no,q,k):
    arrs_n = arrangements_mult_max_k(mset,no)[no]
    arrs_k = arrangements_mult_max_k(mset,floor(k/2))[floor(k/2)]
    pkp_cost = arrs_k / (sqrt(max(1,((arrs_n-1.)/(q^(no-k))))))
    return pkp_cost

def minimum_pkp_value_max_mult(max_mult,no,q,k):
    mset = []
    tot_added = 0
    while no-tot_added > max_mult:
        mset.append(max_mult)
        tot_added += max_mult
    mset.append(no-tot_added)
    return compute_pkp_cost(mset,no,q,k)

def minimum_pkp_value_min_d(min_d,no,q,k):
    mset = [no-min_d]
    for _ in range(min_d-1):
        mset.append(1)
    return compute_pkp_cost(mset,no,q,k)

def vectors_max_mult(max_mult,no,q):
    mult = [max_mult for _ in range(q)]
    num = arrangements_mult_max_k(mult,no)[no]
    return num

def vectors_d(d,no,q):
    vectors = 0
    for k in range(d):
        vectors += ((-1)^(k))*binomial(d,k)*((d-k)^no)
    vectors = binomial(q,d)*vectors
    return vectors
        

def vectors_max_d(max_d,no,q):
    if max_d <= floor(q/2):
        vectors = 0
        for k in range(1,max_d+1):
            vectors += vectors_d(k,no,q)
    else:
        vectors = q^no - vectors_min_d(max_d+1,no,q)
    return vectors

def vectors_min_d(min_d,no,q):
    if min_d >= ceil(q/2):
        vectors = 0
        for k in range(min_d,q+1):
            vectors += vectors_d(k,no,q)
    else:
        vectors = q^no - vectors_max_d(min_d-1,no,q)
    return vectors

if __name__ == '__main__':
    q = 127
    no = 252
    k = 126

    print("======================================")
    print("ANALYSIS BY MIN d")
    min_d = 64
    vec_num = vectors_min_d(min_d,no,q)
    pkp_cost = minimum_pkp_value_min_d(min_d,no,q,k)
    outside = q^no - vec_num
    print("min d:",min_d)
    print("All vectors:",n(log(q^no,2)))
    print("-------------------")
    print(f"Vectors w/ min {min_d} elements:",n(log(vec_num,2)))
    print("Tsample:",n(log((q^no)/vec_num,2)))
    print("-------------------")
    print(f"Vectors w/ less elements:",n(log(outside,2)))
    print("Tsample:",n(log((q^no)/outside,2)))
