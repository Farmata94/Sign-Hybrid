#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "ecdsa_sign.h"


int ecdsa_verify(EC_KEY *ec_key, const char *message, unsigned char *signature, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Hacher le message
    SHA256((unsigned char *)message, strlen(message), hash);

    // Vérifier la signature
    int verify_result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, ec_key);
    if (verify_result != 1) {
        printf("La signature est INVALIDE.\n");
        return 0;
    } else {
        printf("La signature est VALIDÉE.\n");
        return 1;
    }

    /* 5. Nettoyage        */

    free(signature);
    EC_KEY_free(ec_key);
    EVP_cleanup();
    ERR_free_strings();

}
