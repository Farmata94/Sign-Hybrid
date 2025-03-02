#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>
#include <openssl/sha.h>
#include "dilithium/ref/api.h"
#include "dilithium/ref/params.h"

// Taille des clés et des signatures
#define MESSAGE "Hello, this is a test for hybrid signature."
#define MESSAGE_LEN strlen(MESSAGE)

int main() {
    /*========================================*/
    /* 1. Génération des clés DSA et Dilithium */
    /*========================================*/

    // Génération des clés DSA
    DSA *dsa = DSA_new();
    if (!DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL) || !DSA_generate_key(dsa)) {
        fprintf(stderr, "Erreur : échec de la génération des clés DSA.\n");
        DSA_free(dsa);
        return 1;
    }

    // Génération des clés Dilithium
    uint8_t pk_dilithium[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk_dilithium[CRYPTO_SECRETKEYBYTES];
    if (pqcrystals_dilithium2_ref_keypair(pk_dilithium, sk_dilithium) != 0) {
        fprintf(stderr, "Erreur lors de la génération des clés Dilithium.\n");
        return 1;
    }

    printf("Clés DSA et Dilithium générées avec succès.\n");

    /*========================================*/
    /* 2. Signature avec DSA */
    /*========================================*/

    // Hachage du message pour DSA (SHA256)
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)MESSAGE, MESSAGE_LEN, hash);

    // Signature DSA
    unsigned int sig_dsa_len = DSA_size(dsa);
    unsigned char *sig_dsa = malloc(sig_dsa_len);
    if (!sig_dsa || DSA_sign(0, hash, SHA256_DIGEST_LENGTH, sig_dsa, &sig_dsa_len, dsa) != 1) {
        fprintf(stderr, "Erreur lors de la signature DSA.\n");
        free(sig_dsa);
        DSA_free(dsa);
        return 1;
    }

    printf("Message signé avec DSA (%u octets).\n", sig_dsa_len);

    /*========================================*/
    /* 3. Signature avec Dilithium */
    /*========================================*/

    uint8_t sig_dilithium[CRYPTO_BYTES];
    size_t sig_dilithium_len;
    if (pqcrystals_dilithium2_ref_signature(sig_dilithium, &sig_dilithium_len, (const uint8_t *)MESSAGE, MESSAGE_LEN, NULL, 0, sk_dilithium) != 0) {
        fprintf(stderr, "Erreur lors de la signature Dilithium.\n");
        free(sig_dsa);
        DSA_free(dsa);
        return 1;
    }

    printf("Message signé avec Dilithium (%zu octets).\n", sig_dilithium_len);

    /*========================================*/
    /* 4. Combinaison des signatures */
    /*========================================*/

    size_t hybrid_sig_len = sig_dsa_len + sig_dilithium_len;
    unsigned char *hybrid_sig = malloc(hybrid_sig_len);
    if (!hybrid_sig) {
        fprintf(stderr, "Erreur d'allocation pour la signature hybride.\n");
        free(sig_dsa);
        DSA_free(dsa);
        return 1;
    }

    // Concaténer les deux signatures
    memcpy(hybrid_sig, sig_dsa, sig_dsa_len);
    memcpy(hybrid_sig + sig_dsa_len, sig_dilithium, sig_dilithium_len);

    printf("Signature hybride générée (%zu octets).\n", hybrid_sig_len);

    /*========================================*/
    /* 5. Vérification des signatures */
    /*========================================*/

    // Vérification DSA
    int verify_dsa = DSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig_dsa, sig_dsa_len, dsa);
    if (verify_dsa == 1) {
        printf("Signature DSA valide !\n");
    } else {
        printf("Signature DSA invalide !\n");
    }

    // Vérification Dilithium
    int verify_dilithium = pqcrystals_dilithium2_ref_verify(sig_dilithium, sig_dilithium_len, (const uint8_t *)MESSAGE, MESSAGE_LEN, NULL, 0, pk_dilithium);
    if (verify_dilithium == 0) {
        printf("Signature Dilithium valide !\n");
    } else {
        printf("Signature Dilithium invalide !\n");
    }

    /*========================================*/
    /* 6. Nettoyage */
    /*========================================*/
    free(sig_dsa);
    free(hybrid_sig);
    DSA_free(dsa);

    return 0;
}
