def compute_pk_size(n,k,q,keypairs):
    pk_size = (n-k)*k*ceil(log(q,2))*keypairs

    return N(pk_size/(8*1024),digits=5)

def compute_sig_size(k,q,t,keypairs):
    hash_len = 256

    avg_chal_0 = (1/keypairs)*t
    avg_chal_1 = ((keypairs-1)/keypairs)*t

    seed_len = 128
    chal_0_size = seed_len 
    
    chal_1_size = (k)*ceil(log(q,2))

    sig_size = 2*hash_len + avg_chal_0*seed_len + avg_chal_1*chal_1_size 

    return N(sig_size/(8*1024),digits=5)


q = 8191
print(q)
for n,k in [[400,80],[248,112]]:
    print(k)
    for pair in [[41,8],[32,16],[26,32]]:
        print(compute_sig_size(k,q,pair[0],pair[1]), compute_pk_size(n,k,q,pair[1]))

print("===========")

q = 16381
print(q)
for n,k in [[320,80],[274,96]]:
    print(k)
    for pair in [[41,8],[32,16],[26,32]]:
        print(compute_sig_size(k,q,pair[0],pair[1]), compute_pk_size(n,k,q,pair[1]))
