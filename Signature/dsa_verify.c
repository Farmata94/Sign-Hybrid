#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>    // Pour DSA et fonctions associées
#include <openssl/sha.h>    // Pour SHA256
#include <openssl/err.h>    // Pour gérer les erreurs OpenSSL
#include <openssl/pem.h>    // Pour écrire/charger les clés au format PEM
#include "dsa_signature.h"

int dsa_verify(DSA *dsa, const char *message, unsigned char *signature, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // Hacher le message
    SHA256((unsigned char *)message, strlen(message), hash);

    // Vérifier la signature avec la clé publique DSA
    int verify_result = DSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, dsa);
    if (verify_result < 0) {
        fprintf(stderr, "Erreur lors de la vérification de la signature.\n");
        return -1;
    } else if (verify_result == 0) {
        printf("La signature est INVALIDE.\n");
        return 0;
    } else {
        printf("La signature est VALIDÉE.\n");
        return 1;
    }

    free(signature);
    DSA_free(dsa);
    EVP_cleanup();
    ERR_free_strings();
}


    
