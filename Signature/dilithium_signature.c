#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dilithium/ref/api.h"  // Inclut l'API de l'implémentation de référence
#include "dilithium/ref/params.h"


typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} Dilithium_Performance;

/* Fonction pour générer une paire de clés */
int generate_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (pqcrystals_dilithium2_ref_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "Erreur lors de la génération des clés\n");
        return 0;
    }
    printf("Clés générées avec succès.\n");
    return 1;
}

/* Fonction pour signer un message */
int dilithium_sign(const uint8_t *message, size_t message_len, uint8_t *signature, size_t *signature_len, const uint8_t *secret_key) {
    const uint8_t *ctx = NULL;
    size_t ctxlen = 0;

    if (pqcrystals_dilithium2_ref_signature(signature, signature_len, message, message_len, ctx, ctxlen, secret_key) != 0) {
        fprintf(stderr, "Erreur lors de la signature\n");
        return 0;
    }
    printf("Message signé avec succès.\n");
    return 1;
}

/* Fonction pour vérifier une signature */
int dilithium_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    const uint8_t *ctx = NULL;
    size_t ctxlen = 0;

    printf("Vérification de la signature...\n");
    if (pqcrystals_dilithium2_ref_verify(signature, signature_len, message, message_len, ctx, ctxlen, public_key) != 0) {
        printf("Signature invalide.\n");
        return 0;
    }
    printf("Signature valide !\n");
    return 1;
}


/* Fonction pour benchmarker la génération, la signature et la vérification */
void benchmark_dilithium() {
    Dilithium_Performance perf;
    clock_t start, end;


    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t signature[CRYPTO_BYTES];
    size_t signature_len;
    const char *message = "Hello, Dilithium!";
    size_t message_len = strlen(message);
    

    /* Benchmark génération de clé */
    start = clock();
    if (!generate_dilithium_keypair(public_key, secret_key)) return;
    end = clock();
    perf.setup_time = ((double) (end - start)) / CLOCKS_PER_SEC;
    
    /* Benchmark signature */
    start = clock();
    if (!dilithium_sign((const uint8_t *)message, message_len, signature, &signature_len, secret_key)) return;
    end = clock();
    perf.sign_time = ((double) (end - start)) / CLOCKS_PER_SEC;

  

    /* Benchmark vérification */
    start = clock();
    dilithium_verify(signature, signature_len, (const uint8_t *)message, message_len, public_key);
    end = clock();
    perf.verify_time = ((double) (end - start)) / CLOCKS_PER_SEC;



    printf("Dilithium Setup: %.6f\n", perf.setup_time);
    printf("Dilithium Sign: %.6f\n", perf.sign_time);
    printf("Dilithium Verify: %.6f\n", perf.verify_time);
}

