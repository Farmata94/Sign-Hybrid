#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>    // Pour DSA et fonctions associées
#include <openssl/sha.h>    // Pour SHA256
#include <openssl/err.h>    // Pour gérer les erreurs OpenSSL
#include <openssl/pem.h>    // Pour écrire/charger les clés au format PEM
#include <time.h> 

int dsa_sign(void) {
    /*---------------------*/
    /* 1. Initialisation   */
    /*---------------------*/
    // Charge les algorithmes et les chaînes d'erreurs OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /*------------------------------*/
    /* 2. Génération de la clé DSA  */
    /*------------------------------*/
    // Création d'une nouvelle structure DSA
    DSA *dsa = DSA_new();
    if (!dsa) {
        fprintf(stderr, "Erreur : impossible d'allouer la structure DSA.\n");
        return 1;
    }

    // Génération des paramètres DSA (taille : 2048 bits)
    if (!DSA_generate_parameters_ex(dsa, 2048, NULL, 0, NULL, NULL, NULL)) {
        fprintf(stderr, "Erreur : échec de la génération des paramètres DSA.\n");
        DSA_free(dsa);
        return 1;
    }

    // Génération de la paire de clés (privée et publique)
    if (!DSA_generate_key(dsa)) {
        fprintf(stderr, "Erreur : échec de la génération des clés DSA.\n");
        DSA_free(dsa);
        return 1;
    }
    printf("Clé DSA générée avec succès.\n");

    /*---------------------------------------*/
    /* 3. Signature d'un message (DSA_sign)  */
    /*---------------------------------------*/
    // Message à signer
    const char *message = "Hello, this is a test message for DSA signature.";
    
    // Calcul du hachage SHA256 du message
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    // Allocation d'un tampon pour la signature
    unsigned int sig_len = DSA_size(dsa);  // taille maximale de la signature
    unsigned char *signature = malloc(sig_len);
    if (!signature) {
        fprintf(stderr, "Erreur : allocation mémoire pour la signature.\n");
        DSA_free(dsa);
        return 1;
    }

    clock_t start = clock();

    // Signer le hachage avec la clé privée DSA
    if (DSA_sign(0, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, dsa) != 1) {
        fprintf(stderr, "Erreur : échec de la signature du message.\n");
        free(signature);
        DSA_free(dsa);
        return 1;
    }
    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    printf("DSA : %.6f\n", time_spent);

    /*---------------------------------------*/
    /* 4. Vérification de la signature       */
    /*---------------------------------------*/
    // Vérifier la signature à l'aide de la clé publique
    int verify_result = DSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, dsa);
    if (verify_result < 0) {
        fprintf(stderr, "Erreur lors de la vérification de la signature.\n");
    } else if (verify_result == 0) {
        printf("La signature est INVALIDE.\n");
    } else {
        printf("La signature est VALIDÉE.\n");
    }

    /*---------------------*/
    /* 5. Nettoyage        */
    /*---------------------*/
    free(signature);
    DSA_free(dsa);
    EVP_cleanup();
    ERR_free_strings();

    return time_spent;
}
