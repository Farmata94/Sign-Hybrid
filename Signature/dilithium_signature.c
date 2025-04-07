#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "timing.h"
#include <windows.h>  
#include "dilithium/ref/api.h"  
#include "dilithium/ref/params.h"

typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} Dilithium_Performance;

/* Function generate keypair */
int generate_dilithium_keypair(uint8_t *public_key, uint8_t *secret_key) {
    if (pqcrystals_dilithium2_ref_keypair(public_key, secret_key) != 0) {
        fprintf(stderr, "Error during key generation\n");
        return 0;
    }

    return 1;
}

/* Function for sign */
int dilithium_sign(const uint8_t *message, size_t message_len, uint8_t *signature, size_t *signature_len, const uint8_t *secret_key) {
    const uint8_t *ctx = NULL;
    size_t ctxlen = 0;

    if (pqcrystals_dilithium2_ref_signature(signature, signature_len, message, message_len, ctx, ctxlen, secret_key) != 0) {
        fprintf(stderr, "Error during signature\n");
        return 0;
    }

    return 1;
}

/* Function for verify */
int dilithium_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    const uint8_t *ctx = NULL;
    size_t ctxlen = 0;

    if (pqcrystals_dilithium2_ref_verify(signature, signature_len, message, message_len, ctx, ctxlen, public_key) != 0) {
        return 0;
    }

    return 1;
}



int benchmark_dilithium(void) {
    Dilithium_Performance perf;

    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
    uint8_t secret_key[CRYPTO_SECRETKEYBYTES];
    uint8_t signature[CRYPTO_BYTES];
    size_t signature_len = CRYPTO_BYTES;
    const char *message = "Hello, Dilithium!";
    size_t message_len = strlen(message);

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq); 

    /* Generate */
    QueryPerformanceCounter(&start);
    if (!generate_dilithium_keypair(public_key, secret_key)) return 1;
    QueryPerformanceCounter(&end);
    perf.setup_time = get_elapsed_time(start, end, freq);

    /* Benchmark signature */
    QueryPerformanceCounter(&start);
    if (!dilithium_sign((const uint8_t *)message, message_len, signature, &signature_len, secret_key)) return 1;
    QueryPerformanceCounter(&end);
    perf.sign_time = get_elapsed_time(start, end, freq);

    /* Benchmark vérification */
    QueryPerformanceCounter(&start);
    if (!dilithium_verify(signature, signature_len, (const uint8_t *)message, message_len, public_key)) return 1;
    QueryPerformanceCounter(&end);
    perf.verify_time = get_elapsed_time(start, end, freq);

    printf("Dilithium Setup: %.6f s\n", perf.setup_time);
    printf("Dilithium Sign: %.6f s\n", perf.sign_time);
    printf("Dilithium Verify: %.6f s\n", perf.verify_time);

    return 0;
}
