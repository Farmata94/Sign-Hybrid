#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "timing.h"
#include <windows.h> 
#include "liboqs/build/include/oqs/oqs.h"


typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} Falcon_Performance;

//Generate keys
int generate_falcon_keypair(uint8_t **public_key, size_t *public_key_len, uint8_t **secret_key, size_t *secret_key_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) {
        fprintf(stderr, "Erreur lors de l'initialisation de Falcon-512\n");
        return 0;
    }
    *public_key = malloc(sig->length_public_key);
    *secret_key = malloc(sig->length_secret_key);
    if (!*public_key || !*secret_key) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        return 0;
    }
    if (OQS_SIG_keypair(sig, *public_key, *secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur lors de la génération des clés Falcon\n");
        return 0;
    }
    printf("Clés Falcon générées avec succès.\n");
    OQS_SIG_free(sig);
    return 1;
}

// Sign
int falcon_sign(const uint8_t *message, size_t message_len, uint8_t **signature, size_t *signature_len, const uint8_t *secret_key, size_t secret_key_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) return 0;
    *signature = malloc(sig->length_signature);
    if (!*signature) return 0;
    if (OQS_SIG_sign(sig, *signature, signature_len, message, message_len, secret_key) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur lors de la signature Falcon\n");
        return 0;
    }
    printf("Message signé avec succès.\n");
    OQS_SIG_free(sig);
    return 1;
}

// Verify
int falcon_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key, size_t public_key_len) {
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) return 0;
    int result = OQS_SIG_verify(sig, message, message_len, signature, signature_len, public_key) == OQS_SUCCESS;
    printf("Signature Falcon %s.\n", result ? "valide" : "invalide");
    OQS_SIG_free(sig);
    return result;
}




int benchmark_falcon(void) {
    Falcon_Performance perf;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq); 

    uint8_t *public_key = NULL, *secret_key = NULL;
    size_t public_key_len, secret_key_len;
    uint8_t *signature = NULL;
    size_t signature_len;
    const char *message = "Hello, Falcon!";
    size_t message_len = strlen(message);

    // Benchmark génération de clé
    QueryPerformanceCounter(&start);
    if (!generate_falcon_keypair(&public_key, &public_key_len, &secret_key, &secret_key_len)) return 1;
    QueryPerformanceCounter(&end);
    perf.setup_time = get_elapsed_time(start, end, freq);

    // Benchmark signature
    QueryPerformanceCounter(&start);
    if (!falcon_sign((const uint8_t *)message, message_len, &signature, &signature_len, secret_key, secret_key_len)) return 1;
    QueryPerformanceCounter(&end);
    perf.sign_time = get_elapsed_time(start, end, freq);

    // Benchmark verify
    QueryPerformanceCounter(&start);
    perf.verify_result = falcon_verify(signature, signature_len, (const uint8_t *)message, message_len, public_key, public_key_len);
    QueryPerformanceCounter(&end);
    perf.verify_time = get_elapsed_time(start, end, freq);

  
    printf("Falcon Setup: %.6f sec\n", perf.setup_time);
    printf("Falcon Sign: %.6f sec\n", perf.sign_time);
    printf("Falcon Verify: %.6f sec\n", perf.verify_time);

  
    free(public_key);
    free(secret_key);
    free(signature);

    return 0;
}


