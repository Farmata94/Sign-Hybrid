#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium/ref/api.h"  // Inclut l'API de l'implémentation de référence
#include "dilithium/ref/params.h"
#include "dilithium_signature.h"
#include <time.h>  


int dilithium_sign() {
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t signature[CRYPTO_BYTES];
    size_t signature_len;
    const uint8_t *ctx = NULL;  // Pas de contexte utilisé
    size_t ctxlen = 0;
    const char *message = "Hello, Dilithium!";
    size_t message_len = strlen(message);

    // 1. Génération des clés
    if (pqcrystals_dilithium2_ref_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "Erreur lors de la génération des clés\n");
        return 1;
    }

    // 2. Signature
    clock_t start = clock();
    if (pqcrystals_dilithium2_ref_signature(signature, &signature_len, (const uint8_t *)message, message_len, ctx, ctxlen, secret_key) != 0) {
        fprintf(stderr, "Erreur lors de la signature\n");
        return 1;
    }
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Dilithium : %.6f\n", time_spent);
    

    return time_spent;
}

