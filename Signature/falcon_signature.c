#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "PQClean"  // Inclure l'implémentation PQClean de Falcon-512

#define MESSAGE "Hello, Falcon!"

int falcon_sign() {
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    uint8_t sig[CRYPTO_BYTES + strlen(MESSAGE)];
    size_t sig_len;
    uint8_t message[strlen(MESSAGE)];
    uint8_t verified_message[strlen(MESSAGE) + CRYPTO_BYTES];
    size_t verified_message_len;
    
    memcpy(message, MESSAGE, strlen(MESSAGE));
    
    // Génération de clé
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "Erreur de génération de clé\n");
        return EXIT_FAILURE;
    }
    
    // Signature du message
    if (crypto_sign(sig, &sig_len, message, strlen(MESSAGE), sk) != 0) {
        fprintf(stderr, "Erreur lors de la signature\n");
        return EXIT_FAILURE;
    }
    
    printf("Signature réussie!\n");
    
    // Vérification de la signature
    if (crypto_sign_open(verified_message, &verified_message_len, sig, sig_len, pk) != 0) {
        fprintf(stderr, "Signature invalide!\n");
        return EXIT_FAILURE;
    }
    
    printf("Signature valide!\n");
    return EXIT_SUCCESS;
}

