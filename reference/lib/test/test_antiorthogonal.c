#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "monomial_mat.h"
#include "codes.h"
#include "canonical.h"
#include "cf_test.h"
#define ITERS 100

int main(void) {
    unsigned char compressed_sk[PRIVATE_KEY_SEED_LENGTH_BYTES];
    randombytes(compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    SHAKE_STATE_STRUCT sk_shake_state;
    initialize_csprng(&sk_shake_state, compressed_sk, PRIVATE_KEY_SEED_LENGTH_BYTES);
    unsigned char G_seed[SEED_LENGTH_BYTES];
    csprng_randombytes(G_seed, SEED_LENGTH_BYTES, &sk_shake_state);

    FQ_ELEM A[K][K];
    antiorthogonal_sample(A,G_seed);
    for(uint8_t i=0; i < K; i++){
        for(uint8_t j=0; j < K; j++){
            printf(" %i ",fq_mul(A[i][j],A[j][i]));
        }
        printf("\n");
    }

    printf("Done, all worked\n");
    return 0;
}
