#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium/ref/api.h"  // Inclut l'API de l'implémentation de référence
#include "dilithium/ref/params.h"


int main() {
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
    if (pqcrystals_dilithium2_ref_signature(signature, &signature_len, (const uint8_t *)message, message_len, ctx, ctxlen, secret_key) != 0) {
        fprintf(stderr, "Erreur lors de la signature\n");
        return 1;
    }

    // 3. Vérification
    if (pqcrystals_dilithium2_ref_verify(signature, signature_len, (const uint8_t *)message, message_len, ctx, ctxlen, public_key) != 0) {
        fprintf(stderr, "Signature invalide\n");
        return 1;
    }

    printf("Signature valide !\n");

    // Optionnel : afficher la signature en hexadécimal
    printf("Signature : ");
    for (size_t i = 0; i < signature_len; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    return 0;
}

