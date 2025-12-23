
/**
 * @file main.c
 * @brief NIST api test
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include "api.h"
#include "parameters.h"
#include "rng.h"

static void init_randomness(void) {
    unsigned char seed[48] = {0};

#ifndef VERBOSE
    if (0 != getentropy(seed, sizeof(seed))) {
        printf("failed to get entropy for randombytes()\n");
        exit(1);
    }
#endif

    randombytes_init(seed, NULL, 256);
}

int main(void) {
    init_randomness();

    printf("\n");
    printf("*****************************\n");
    printf("**** %s-%d ****\n", CRYPTO_ALGNAME, PERK_SECURITY_BYTES * 8);
    printf("*****************************\n");

    printf("\n");
    printf("n: %d   ", PERK_PARAM_N);
    printf("m: %d   ", PERK_PARAM_M);
    printf("Q: %d   ", PERK_PARAM_Q);
    printf("N: %d   ", PERK_PARAM_N);
    printf("tau: %d   ", PERK_PARAM_TAU);
    printf("Sec: %d bits   ", PERK_SECURITY_BYTES * 8);
    printf("Public key size: %d   ", CRYPTO_PUBLICKEYBYTES);
    printf("Private key size: %d   ", CRYPTO_SECRETKEYBYTES);
    printf("Signature size: %d   ", CRYPTO_BYTES);
    printf("\n");

    unsigned char pk[CRYPTO_PUBLICKEYBYTES] = {0};
    unsigned char sk[CRYPTO_SECRETKEYBYTES] = {0};

    unsigned char m[32] = {0};
    size_t mlen = sizeof(m);

    size_t smlen;
    unsigned char sm[sizeof(m) + CRYPTO_BYTES] = {0};

    int ret;

    ret = crypto_sign_keypair(pk, sk);
    if (ret != 0) {
        printf("\ncrypto_sign_keypair failed\n");
        return ret;
    }

    ret = crypto_sign(sm, &smlen, m, sizeof(m), sk);
    if (ret != 0) {
        printf("\ncrypto_sign failed\n");
        return ret;
    }

    ret = crypto_sign_open(m, &mlen, sm, smlen, pk);
    if (ret != 0) {
        printf("\ncrypto_sign_open failed\n");
    } else {
        printf("\nSignature verification successful");
    }

    printf("\n\n");

    return ret;
}
