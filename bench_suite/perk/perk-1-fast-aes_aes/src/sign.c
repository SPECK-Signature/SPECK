
/**
 * @file sign.c
 * @brief Implementation of api function
 */

#include "api.h"
#include "crypto_memset.h"
#include "data_structures.h"
#include "keygen.h"
#include "parameters.h"
#include "parsing.h"
#include "signature.h"
#include "verbose.h"
#include "verify.h"

const size_t pk_offset = (PERK_PRIVATE_KEY_BYTES - PERK_PUBLIC_KEY_BYTES);

/**
 * @brief Generate a keypair.
 *
 * @param [out] pk pointer to public key bytes
 * @param [out] sk pointer to public key bytes
 * @returns 0 if key generation is successful and -1 otherwise
 */
int crypto_sign_keypair(unsigned char *pk, unsigned char *sk) {
    SIG_PERK_VERBOSE_PRINT_string("KEYGEN");
    sig_perk_public_key_t public_key = {0};
    sig_perk_private_key_t private_key = {0};

    if (sig_perk_generate_keypair(&public_key, &private_key) != PERK_SUCCESS) {
        memset_zero(&private_key, sizeof(private_key));
        return -1;
    }

    sig_perk_public_key_to_bytes(pk, &public_key);
    sig_perk_private_key_to_bytes(sk, &private_key);
    memcpy(sk + pk_offset, pk, PERK_PUBLIC_KEY_BYTES);

    memset_zero(&private_key, sizeof(private_key));

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("pk", pk, PERK_PUBLIC_KEY_BYTES);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("sk", sk, PERK_PRIVATE_KEY_BYTES);

    return 0;
}

int crypto_sign(unsigned char *sm, size_t *smlen, const unsigned char *m, size_t mlen, const unsigned char *sk) {
    SIG_PERK_VERBOSE_PRINT_string("SIGN");

    sig_perk_private_key_t sk_struct = {0};
    sig_perk_public_key_t pk_struct = {0};
    sig_perk_signature_t signature = {0};
    digest_t mu = {0};

    sig_perk_private_key_from_bytes(&sk_struct, sk);
    if (PERK_SUCCESS != sig_perk_public_key_from_bytes(&pk_struct, sk + pk_offset)) {
        goto clean;
    }
    // Compute mu
    sig_perk_hash_state_t state_H1 = {0};
    sig_perk_hash_init(&state_H1, NULL, NULL, NULL);
    sig_perk_hash_update(&state_H1, sk + pk_offset, PERK_PUBLIC_KEY_BYTES);
    sig_perk_hash_update(&state_H1, m, mlen);
    sig_perk_hash_final(&state_H1, mu, H1);

    SIG_PERK_VERBOSE_PRINT_uint8_t_array("message m", m, mlen);
    SIG_PERK_VERBOSE_PRINT_uint8_t_array("mu", mu, sizeof(digest_t));

    if (PERK_SUCCESS != sig_perk_sign(&signature, mu, &sk_struct, &pk_struct)) {
        goto clean;
    }

    for (size_t i = 0; i < mlen; ++i) sm[CRYPTO_BYTES + mlen - 1 - i] = m[mlen - 1 - i];

    sig_perk_signature_to_bytes(sm, &signature);
    memset_zero(&pk_struct, sizeof(pk_struct));

    *smlen = mlen + CRYPTO_BYTES;

    SIG_PERK_VERBOSE_PRINT_signature_raw(m, mlen, sm);

    return 0;
clean:
    memset_zero(&pk_struct, sizeof(pk_struct));
    memset_zero(&signature, sizeof(signature));
    return -1;
}

int crypto_sign_open(unsigned char *m, size_t *mlen, const unsigned char *sm, size_t smlen, const unsigned char *pk) {
    SIG_PERK_VERBOSE_PRINT_string("SIGN OPEN");

    if (smlen < CRYPTO_BYTES)
        goto clean;

    sig_perk_public_key_t pk_struct = {0};
    sig_perk_signature_t signature = {0};
    digest_t mu = {0};

    if (PERK_SUCCESS != sig_perk_public_key_from_bytes(&pk_struct, pk)) {
        goto clean;
    }
    if (PERK_SUCCESS != sig_perk_signature_from_bytes(&signature, sm)) {
        goto clean;
    }

    // Compute mu
    sig_perk_hash_state_t state_H1 = {0};
    sig_perk_hash_init(&state_H1, NULL, NULL, NULL);
    sig_perk_hash_update(&state_H1, pk, PERK_PUBLIC_KEY_BYTES);
    sig_perk_hash_update(&state_H1, (uint8_t *)(sm + CRYPTO_BYTES), smlen - CRYPTO_BYTES);
    sig_perk_hash_final(&state_H1, mu, H1);

    *mlen = smlen - CRYPTO_BYTES;

    // check the signature
    if (PERK_SUCCESS != sig_perk_verify(&signature, mu, &pk_struct)) {
        goto clean;
    } else {
        /* All good, copy msg, return 0 */
        for (size_t i = 0; i < *mlen; ++i) m[i] = sm[CRYPTO_BYTES + i];
        return 0;
    }

clean:
    /* Signature verification failed */
    *mlen = -1;
    return -1;
}
