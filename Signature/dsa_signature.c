#include <stdio.h>
#include <stdlib.h>
#include <windows.h> 
#include <string.h>
#include "timing.h"
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>

// Structure pour stocker les clés
typedef struct {
    DSA *dsa;
} DSA_Keys;

// Structure pour stocker les résultats
typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} DSA_Performance;

// Génération des clés DSA
DSA_Keys setup_dsa() {
    DSA *dsa = DSA_new();
    DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL);
    DSA_generate_key(dsa);
    
    return (DSA_Keys){dsa};
}

// Signature d'un message
unsigned char* dsa_sign(DSA *dsa, unsigned int *sig_len) {
    const char *message = "Hello, DSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char *signature = malloc(DSA_size(dsa));
    DSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, dsa);
    
    return signature;
}

// Vérification d'une signature
int dsa_verify(DSA *dsa, unsigned char *signature, unsigned int sig_len) {
    const char *message = "Hello, DSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    
    return DSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, dsa);
}


// Benchmark complet
int benchmark_dsa(void) {
    DSA_Performance perf;

    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);  

    // setup
    QueryPerformanceCounter(&start);
    DSA_Keys keys = setup_dsa();
    QueryPerformanceCounter(&end);
    perf.setup_time = get_elapsed_time(start, end, freq);

    // Sign
    unsigned int sig_len;
    QueryPerformanceCounter(&start);
    unsigned char *signature = dsa_sign(keys.dsa, &sig_len);
    QueryPerformanceCounter(&end);
    perf.sign_time = get_elapsed_time(start, end, freq);

    // Verification
    QueryPerformanceCounter(&start);
    perf.verify_result = dsa_verify(keys.dsa, signature, sig_len);
    QueryPerformanceCounter(&end);
    perf.verify_time = get_elapsed_time(start, end, freq);

    // Benchmark
    printf("DSA Setup: %.6f s\n", perf.setup_time);
    printf("DSA Sign: %.6f s\n", perf.sign_time);
    printf("DSA Verify: %.6f s\n", perf.verify_time);

    free(signature);
    DSA_free(keys.dsa);

    return 0;
}

