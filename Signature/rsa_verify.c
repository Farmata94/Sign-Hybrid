#include "rsa_sign.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>


int rsa_verify(RSA *rsa, const char *message, unsigned char *signature, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Hacher le message
    SHA256((unsigned char *)message, strlen(message), hash);

    // Vérifier la signature
    int verify_result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
    if (verify_result != 1) {
        printf("La signature est INVALIDE.\n");
        return 0;
    } else {
        printf("La signature est VALIDÉE.\n");
        return 1;
    }
     /* 5. Nettoyage        */
     free(signature);
     RSA_free(rsa);
     EVP_cleanup();
     ERR_free_strings();
}
