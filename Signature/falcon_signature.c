#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "falcon.h"

#define MESSAGE "Bonjour, ceci est un message signé avec Falcon!"

int falcon_sign() {
    // Buffers pour les clés, signature et message
    uint8_t sk[1280];  // Clé privée (taille maximale pour Falcon-1024)
    uint8_t pk[1024];  // Clé publique
    uint8_t sig[1024]; // Signature
    size_t sig_len;
    
    // Génération de la clé (Falcon-512)
    if (falcon_keygen_make(9, sk, sizeof(sk), pk, sizeof(pk), NULL, 0) != 0) {
        fprintf(stderr, "Erreur lors de la génération des clés\n");
        return EXIT_FAILURE;
    }

    printf("Clés générées avec succès !\n");

    // Signature du message
    if (falcon_sign_dyn(9, sig, &sig_len, sk, MESSAGE, strlen(MESSAGE), NULL, 0) != 0) {
        fprintf(stderr, "Erreur lors de la signature\n");
        return EXIT_FAILURE;
    }

    printf("Message signé avec succès !\n");

    // Vérification de la signature
    if (falcon_verify(9, sig, sig_len, pk, MESSAGE, strlen(MESSAGE)) != 0) {
        fprintf(stderr, "Signature invalide !\n");
        return EXIT_FAILURE;
    }

    printf("Signature vérifiée avec succès !\n");

    return EXIT_SUCCESS;
}
