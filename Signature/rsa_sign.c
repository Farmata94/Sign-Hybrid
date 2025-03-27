#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>

// Structure pour stocker les clés
typedef struct {
    RSA *rsa;
    BIGNUM *e;
} RSA_Keys;

// Structure pour stocker les résultats
typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} RSA_Performance;

// Génération des clés RSA
RSA_Keys setup_rsa() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    
    return (RSA_Keys){rsa, e};
}

// Signature d'un message
unsigned char* rsa_sign(RSA *rsa, unsigned int *sig_len) {
    const char *message = "Hello, RSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char *signature = malloc(RSA_size(rsa));
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
    
    return signature;
}

// Vérification d'une signature
int rsa_verify(RSA *rsa, unsigned char *signature, unsigned int sig_len) {
    const char *message = "Hello, RSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    
    return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
}

// Benchmark complet
int benchmark_rsa(void) {
    RSA_Performance perf;
    clock_t start, end;

    // Mesure du temps de setup
    start = clock();
    RSA_Keys keys = setup_rsa();
    end = clock();
    perf.setup_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Mesure du temps de signature
    unsigned int sig_len;
    start = clock();
    unsigned char *signature = rsa_sign(keys.rsa, &sig_len);
    end = clock();
    perf.sign_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Mesure du temps de vérification
    start = clock();
    perf.verify_result = rsa_verify(keys.rsa, signature, sig_len);
    end = clock();
    perf.verify_time = (double)(end - start) / CLOCKS_PER_SEC;

    // Affichage des performances
    printf("RSA Setup: %.6f\n", perf.setup_time);
    printf("RSA Sign: %.6f\n", perf.sign_time);
    printf("RSA Verify: %.6f\n", perf.verify_time);

    free(signature);
    RSA_free(keys.rsa);
    BN_free(keys.e);
}

