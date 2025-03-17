#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
void benchmark_dsa() {
    DSA_Performance perf;
    clock_t start, end;

    // Mesure du temps de setup
    start = clock();
    DSA_Keys keys = setup_dsa();
    end = clock();
    perf.setup_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Mesure du temps de signature
    unsigned int sig_len;
    start = clock();
    unsigned char *signature = dsa_sign(keys.dsa, &sig_len);
    end = clock();
    perf.sign_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Mesure du temps de vérification
    start = clock();
    perf.verify_result = dsa_verify(keys.dsa, signature, sig_len);
    end = clock();
    perf.verify_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Affichage des performances
    printf("DSA Setup: %.6f\n", perf.setup_time);
    printf("DSA Sign: %.6f\n", perf.sign_time);
    printf("DSA Verify: %.6f\n", perf.verify_time);

    free(signature);
    DSA_free(keys.dsa);
}

