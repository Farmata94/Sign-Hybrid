#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "liboqs/build/include/oqs/oqs.h"
#include "liboqs/build/include/oqs/sig_falcon.h"  // bibliothèque Falcon (libpqcrypto)
#include <time.h>  

#define MESSAGE "Bonjour, ceci est un message signé avec Falcon!"
#define SIG_SIZE 1024  // Taille de la signature (dépend du niveau de Falcon, ici Falcon-512)

int falcon_sign() {
    uint8_t sk[1024];  // Clé privée
    uint8_t pk[1024];  // Clé publique
    uint8_t signature[SIG_SIZE];
    size_t sig_len = SIG_SIZE;
    
    // Générer la paire de clés Falcon
    if (OQS_SIG_falcon_512_keypair(sk, pk) != 0) {
        fprintf(stderr, "Erreur lors de la génération des clés Falcon\n");
        return 1;
    }
    printf("Clés Falcon générées avec succès!\n");

    // Message à signer
    const uint8_t *message = (const uint8_t *)MESSAGE;
    size_t message_len = strlen(MESSAGE);
    
    // Signer le message
    clock_t start = clock();
    if (OQS_SIG_falcon_512_sign(signature, &sig_len, message, message_len, sk) != 0) {
        fprintf(stderr, "Erreur lors de la signature du message\n");
        return 1;
    }
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    printf("Falcon : %.6f\n", time_spent);

    // Vérifier la signature
    if (OQS_SIG_falcon_512_verify(signature, sig_len, message, message_len, pk) != 0) {
        fprintf(stderr, "Échec de la vérification de la signature!\n");
        return 1;
    }
    printf("Signature vérifiée avec succès!\n");

    return time_spent;
}