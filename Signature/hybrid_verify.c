#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dsa_signature.h"
#include "rsa_sign.h"
#include "ecdsa_sign.h"
// #include "falcon_signature.h"
#include "dilithium_signature.h"
// #include "phinics_sign.h"
#include "dilithium/ref/api.h" // Pour Dilithium
#include "dilithium/ref/params.h"
// #include "liboqs/build/include/oqs/oqs.h"
// #include "liboqs/build/include/oqs/sig_falcon.h"  // bibliothèque Falcon (libpqcrypto)


// Lire le fichier
int read_file(const char *filename, unsigned char **buffer, size_t *length) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", filename);
        return -1;
    }

    fseek(file, 0, SEEK_END);
    *length = ftell(file);
    rewind(file);

    *buffer = malloc(*length);
    fread(*buffer, 1, *length, file);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <file> <trad_algo> <hybrid_algo> \n", argv[0]);
        return 1;
    }

    char *file_path = argv[1], *trad_algo = argv[2], *hybrid_algo = argv[3];

    unsigned char *message, *trad_signature = NULL, *hybrid_signature = NULL;
    size_t message_len, hybrid_sig_len;
    unsigned int trad_sig_len;
    double total_time = 0;
    
    if (read_file(file_path, &message, &message_len)) return 1;

    // Trad sign

    if (strcmp(trad_algo, "DSA") == 0) {
        DSA *dsa = DSA_new();
        dsa_verify(dsa, trad_signature, trad_sig_len);
    } else if (strcmp(trad_algo, "RSA") == 0) {
        RSA *rsa = RSA_new();
        rsa_verify(rsa, trad_signature, trad_sig_len);
    } else if (strcmp(trad_algo, "ECDSA") == 0) {
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        ecdsa_verify(ec_key, message, trad_signature, trad_sig_len);
    } else {
        fprintf(stderr, "Algorithme traditionnel inconnu : %s\n", trad_algo);
        return 1;
    }


    // Post-quantique Sign

    if (strcmp(hybrid_algo, "Dilithium") == 0) {
        uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
        dilithium_verify( hybrid_signature,  hybrid_sig_len, (const uint8_t *)message, message_len,public_key);
    // } else if (strcmp(hybrid_algo, "Falcon") == 0) {
    //     falcon_sign(message, message_len, &hybrid_signature, &hybrid_sig_len);
    // } else if (strcmp(hybrid_algo, "Phinics") == 0) {
    //     phinics_sign(message, message_len, &hybrid_signature, &hybrid_sig_len);
    } else {
        fprintf(stderr, "Algorithme hybride inconnu : %s\n", hybrid_algo);
        return 1;
    }
   

    free(message);
    free(trad_signature);
    free(hybrid_signature);
    return 0;
}