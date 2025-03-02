#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/pem.h> 

int ecdsa_sign(void) {

    /* 1. Initialisation   */

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();


    /* 2. Génération de la clé ECDSA  */
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec_key || !EC_KEY_generate_key(ec_key)) {
        fprintf(stderr, "Erreur : échec de la génération des clés ECDSA.\n");
        EC_KEY_free(ec_key);
        return 1;
    }
    printf("Clé ECDSA générée avec succès.\n");


    /* 3. Signature d'un message (ECDSA_sign)    */

    const char *message = "Hello, this is a test message for ECDSA signature.";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)message, strlen(message), hash);

    unsigned char *signature = NULL;
    unsigned int sig_len = 0;
    sig_len = ECDSA_size(ec_key);
    signature = malloc(sig_len);
    
    if (!signature) {
        fprintf(stderr, "Erreur : allocation mémoire pour la signature.\n");
        EC_KEY_free(ec_key);
        return 1;
    }

    if (!ECDSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, signature, &sig_len, ec_key)) {
        fprintf(stderr, "Erreur : échec de la signature du message.\n");
        free(signature);
        EC_KEY_free(ec_key);
        return 1;
    }
    printf("Message signé avec succès.\nSignature (en %u octets).\n", sig_len);


    /* 4. Vérification de la signature (ECDSA_verify) */

    int verify_result = ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, signature, sig_len, ec_key);
    if (verify_result != 1) {
        printf("La signature est INVALIDE.\n");
    } else {
        printf("La signature est VALIDÉE.\n");
    }


    /* 5. Nettoyage        */

    free(signature);
    EC_KEY_free(ec_key);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}