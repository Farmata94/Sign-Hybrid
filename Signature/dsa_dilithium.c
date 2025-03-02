#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>       // Pour DSA
#include <openssl/sha.h>       // Pour SHA256
#include "dilithium/ref/api.h" // Pour Dilithium
#include "dilithium/ref/params.h"

#define MESSAGE "Hello, Hybrid Signature!"

void print_hex(const char *label, const unsigned char *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    printf("\n");
}

int dsa_dilithium() {
    /*------------------------------*/
    /* 1. Génération des clés       */
    /*------------------------------*/
    // DSA
    DSA *dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "Erreur d'allocation DSA.\n");
        return 1;
    }
    if (!DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL)) {
        fprintf(stderr, "Erreur de génération des paramètres DSA.\n");
        DSA_free(dsa);
        return 1;
    }
    if (!DSA_generate_key(dsa)) {
        fprintf(stderr, "Erreur de génération des clés DSA.\n");
        DSA_free(dsa);
        return 1;
    }

    // Dilithium
    uint8_t dilithium_pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t dilithium_sk[CRYPTO_SECRETKEYBYTES];
    if (pqcrystals_dilithium2_ref_keypair(dilithium_pk, dilithium_sk) != 0) {
        fprintf(stderr, "Erreur de génération des clés Dilithium.\n");
        DSA_free(dsa);
        return 1;
    }

    /*------------------------------*/
    /* 2. Signature du message      */
    /*------------------------------*/
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)MESSAGE, strlen(MESSAGE), hash);

    // Signature DSA
    unsigned int dsa_sig_len = DSA_size(dsa);
    unsigned char *dsa_signature = malloc(dsa_sig_len);
    if (!dsa_signature) {
        fprintf(stderr, "Erreur d'allocation mémoire pour la signature DSA.\n");
        DSA_free(dsa);
        return 1;
    }

    if (DSA_sign(0, hash, SHA256_DIGEST_LENGTH, dsa_signature, &dsa_sig_len, dsa) != 1) {
        fprintf(stderr, "Erreur de signature DSA.\n");
        free(dsa_signature);
        DSA_free(dsa);
        return 1;
    }
    
    // Signature Dilithium
    uint8_t dilithium_sig[CRYPTO_BYTES];
    size_t dilithium_sig_len;
    
    if (pqcrystals_dilithium2_ref_signature(dilithium_sig, &dilithium_sig_len, 
        (const uint8_t *)MESSAGE, strlen(MESSAGE), NULL, 0, dilithium_sk) != 0) {
        fprintf(stderr, "Erreur de signature Dilithium.\n");
        free(dsa_signature);
        DSA_free(dsa);
        return 1;
    }
   
    // Afficher les signatures
    print_hex("Signature DSA", dsa_signature, dsa_sig_len);
    print_hex("Signature Dilithium", dilithium_sig, dilithium_sig_len);

    /*------------------------------*/
    /* 3. Vérification des signatures */
    /*------------------------------*/
    int dsa_valid = DSA_verify(0, hash, SHA256_DIGEST_LENGTH, dsa_signature, dsa_sig_len, dsa);
    int dilithium_valid = pqcrystals_dilithium2_ref_verify(dilithium_sig, dilithium_sig_len, 
        (const uint8_t *)MESSAGE, strlen(MESSAGE), NULL, 0, dilithium_pk);

    if (dsa_valid == 1 && dilithium_valid == 0) {
        printf("✅ Signature hybride VALIDÉE.\n");
    } else {
        printf("❌ Signature hybride INVALIDE.\n");
    }

    /*------------------------------*/
    /* 4. Nettoyage                 */
    /*------------------------------*/
    free(dsa_signature);
    DSA_free(dsa);

    return 0;
}
