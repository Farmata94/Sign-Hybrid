#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <time.h>  

int rsa_sign(void) {

    /* 1. Initialisation   */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* 2. Génération de la clé RSA  */
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    if (!RSA_generate_key_ex(rsa, 2048, e, NULL)) {
        fprintf(stderr, "Erreur : échec de la génération des clés RSA.\n");
        RSA_free(rsa);
        BN_free(e);
        return 1;
    }
    printf("Clé RSA générée avec succès.\n");

    /* 3. Signature d'un message (RSA_sign)  */
    const char *message = "Hello, this is a test message for RSA signature.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char *signature = malloc(RSA_size(rsa));
    unsigned int sig_len;
    
    if (!signature) {
        fprintf(stderr, "Erreur : allocation mémoire pour la signature.\n");
        RSA_free(rsa);
        BN_free(e);
        return 1;
    }

    // Démarrer le chronomètre
    clock_t start = clock();

    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, rsa) != 1) {
        fprintf(stderr, "Erreur : échec de la signature du message.\n");
        free(signature);
        RSA_free(rsa);
        BN_free(e);
        return 1;
    }

    // Arrêter le chronomètre
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    printf("RSA :%.6f\n", time_spent);
    
    /* 4. Vérification de la signature       */
    int verify_result = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, sig_len, rsa);
    if (verify_result != 1) {
        printf("La signature est INVALIDE.\n");
    } else {
        printf("La signature est VALIDÉE.\n");
    }

    /* 5. Nettoyage        */
    free(signature);
    RSA_free(rsa);
    BN_free(e);
    EVP_cleanup();
    ERR_free_strings();

    return time_spent;
}
