#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "timing.h"
#include <windows.h> 
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h>

typedef struct {
    double setup_time;
    double sign_time;
    double verify_time;
    int verify_result;
} ECDSA_Performance;

/* Initialization OpenSSL */
void setup() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

/* Generate ECDSA Key*/
EC_KEY* generate_ecdsa_key() {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Erreur : échec de la génération des clés ECDSA.\n");
        if (ec_key) EC_KEY_free(ec_key);
        return NULL;
    }
    printf("Clé ECDSA générée avec succès.\n");
    return ec_key;
}

/* Sign a message */
int ecdsa_sign(EC_KEY *ec_key, const char *message, unsigned char **signature, unsigned int *sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    *signature = NULL;  
    *sig_len = ECDSA_size(ec_key);
    *signature = malloc(*sig_len);
    if (!*signature) {
        fprintf(stderr, "Erreur : allocation mémoire pour la signature.\n");
        return 0;
    }

    if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, *signature, sig_len, ec_key)) {
        fprintf(stderr, "Erreur : échec de la signature du message.\n");
        free(*signature);
        *signature = NULL;  
        return 0;
    }

    printf("Message signé avec succès (%u octets).\n", *sig_len);
    return 1;
}


/* Verify a message */
int ecdsa_verify(EC_KEY *ec_key, const char *message, unsigned char *signature, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    int verify_result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, ec_key);
    if (verify_result == 1) {
        printf("La signature est VALIDÉE.\n");
    } else if (verify_result == 0) {
        printf("La signature est INVALIDE.\n");
    } else {
        fprintf(stderr, "Erreur lors de la vérification : %s\n", ERR_error_string(ERR_get_error(), NULL));
    }
    return verify_result;
}

/* Main Function*/
int benchmark_ecdsa(void) {
    ECDSA_Performance perf = {0};  
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);

    setup();  

    /* Benchmark génération */
    QueryPerformanceCounter(&start);
    EC_KEY *ec_key = generate_ecdsa_key();
    QueryPerformanceCounter(&end);
    perf.setup_time = get_elapsed_time(start, end, freq);

    /* Benchmark signature */
    const char *message = "Hello, this is a test message for ECDSA signature.";
    unsigned char *signature = NULL;
    unsigned int sig_len = 0;

    QueryPerformanceCounter(&start);
    perf.sign_time= ecdsa_sign(ec_key, message, &signature, &sig_len);
    QueryPerformanceCounter(&end);
    perf.sign_time = get_elapsed_time(start, end, freq);


    /* Benchmark vérification */
    QueryPerformanceCounter(&start);
    perf.verify_result = ecdsa_verify(ec_key, message, signature, sig_len);
    QueryPerformanceCounter(&end);
    perf.verify_time = get_elapsed_time(start, end, freq);


  
    free(signature);
    EC_KEY_free(ec_key);
    EVP_cleanup();
    ERR_free_strings();

    printf("ECDSA Setup: %.6f sec\n", perf.setup_time);
    printf("ECDSA Sign: %.6f sec\n", perf.sign_time);
    printf("ECDSA Verify: %.6f sec\n", perf.verify_time);
    return 0;
}

