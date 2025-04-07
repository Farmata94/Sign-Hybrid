#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h> 
#include "timing.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>


typedef struct {
    RSA *rsa;
    BIGNUM *e;
} RSA_Keys;


typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} RSA_Performance;

// Generate keys
RSA_Keys setup_rsa() {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    
    return (RSA_Keys){rsa, e};
}

// Sign
unsigned char* rsa_sign(RSA *rsa, unsigned int *sig_len) {
    const char *message = "Hello, RSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char *signature = malloc(RSA_size(rsa));
    RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
    
    return signature;
}

// Verify
int rsa_verify(RSA *rsa, unsigned char *signature, unsigned int sig_len) {
    const char *message = "Hello, RSA test message.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);
    
    return RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
}



int benchmark_rsa(void) {
    RSA_Performance perf;
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);  


    
    QueryPerformanceCounter(&start);
    RSA_Keys keys = setup_rsa();
    QueryPerformanceCounter(&end);
    perf.setup_time = get_elapsed_time(start, end, freq);


    unsigned int sig_len;
    QueryPerformanceCounter(&start);
    unsigned char *signature = rsa_sign(keys.rsa, &sig_len);
    QueryPerformanceCounter(&end);
    perf.sign_time = get_elapsed_time(start, end, freq);

 
    QueryPerformanceCounter(&start);
    perf.verify_result = rsa_verify(keys.rsa, signature, sig_len);
    QueryPerformanceCounter(&end);
    perf.verify_time = get_elapsed_time(start, end, freq);


    printf("RSA Setup: %.6f\n", perf.setup_time);
    printf("RSA Sign: %.6f\n", perf.sign_time);
    printf("RSA Verify: %.6f\n", perf.verify_time);

    free(signature);
    RSA_free(keys.rsa);
    BN_free(keys.e);
}

