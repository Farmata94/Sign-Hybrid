#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
/* Fonction d'initialisation OpenSSL */
void setup() {
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
}

/* Fonction pour générer une clé ECDSA */
EC_KEY* generate_ecdsa_key() {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Erreur : échec de la génération des clés ECDSA.\n");
        EC_KEY_free(ec_key);
        return NULL;
    }
    printf("Clé ECDSA générée avec succès.\n");
    return ec_key;
}

/* Fonction pour signer un message */
int ecdsa_sign(EC_KEY *ec_key, const char *message, unsigned char **signature, unsigned int *sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    *sig_len = ECDSA_size(ec_key);
    *signature = malloc(*sig_len);
    if (!*signature) {
        fprintf(stderr, "Erreur : allocation mémoire pour la signature.\n");
        return 0;
    }

    if (!ECDSA_sign(0, hash, SHA256_DIGEST_LENGTH, *signature, sig_len, ec_key)) {
        fprintf(stderr, "Erreur : échec de la signature du message.\n");
        free(*signature);
        return 0;
    }
    printf("Message signé avec succès.\nSignature (en %u octets).\n", *sig_len);
    return 1;
}

/* Fonction pour vérifier la signature */
int ecdsa_verify(EC_KEY *ec_key, const char *message, unsigned char *signature, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    int verify_result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, ec_key);
    if (verify_result != 1) {
        printf("La signature est INVALIDE.\n");
    } else {
        printf("La signature est VALIDÉE.\n");
    }
    return verify_result;
}

/* Fonction pour benchmarker la génération, la signature et la vérification */
void benchmark_ecdsa() {
    ECDSA_Performance perf;
    clock_t start, end;
 

    setup();

    /* Benchmark génération */
    start = clock();
    EC_KEY *ec_key = generate_ecdsa_key();
    end = clock();
    if (!ec_key) return;
    perf.setup_time = ((double) (end - start)) / CLOCKS_PER_SEC;
   

    /* Benchmark signature */
    const char *message = "Hello, this is a test message for ECDSA signature.";
    unsigned char *signature = NULL;
    unsigned int sig_len = 0;

    start = clock();
    if (!ecdsa_sign(ec_key, message, &signature, &sig_len)) {
        EC_KEY_free(ec_key);
        return;
    }
    end = clock();
    perf.sign_time = ((double) (end - start)) / CLOCKS_PER_SEC;
    

    /* Benchmark vérification */
    start = clock();
    ecdsa_verify(ec_key, message, signature, sig_len);
    end = clock();
    perf.verify_time = ((double) (end - start)) / CLOCKS_PER_SEC;
   

    /* Nettoyage */
    free(signature);
    EC_KEY_free(ec_key);
    EVP_cleanup();
    ERR_free_strings();

    printf("ECDSA Setup: %.6f\n", perf.setup_time);
    printf("ECDSA Sign: %.6f\n", perf.sign_time);
    printf("ECDSA Verify: %.6f\n", perf.verify_time);
}
