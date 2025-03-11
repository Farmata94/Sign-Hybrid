// #include <stdio.h>
// #include <stdlib.h>
// #include <string.h>
// #include "dsa_signature.h"
// #include "rsa_sign.h"
// #include "ecdsa_sign.h"
// // #include "falcon_signature.h"
// #include "dilithium_signature.h"
// // #include "phinics_sign.h"
// #include "dilithium/ref/api.h" // Pour Dilithium
// #include "dilithium/ref/params.h"
// // #include "liboqs/build/include/oqs/oqs.h"
// // #include "liboqs/build/include/oqs/sig_falcon.h"  // bibliothèque Falcon (libpqcrypto)


// // Lire le fichier signé et récupérer les signatures
// int read_signed_file(const char *filename, unsigned char **trad_sig, unsigned int *trad_sig_len, 
//                      unsigned char **hybrid_sig, size_t *hybrid_sig_len) {
//     FILE *file = fopen(filename, "rb");
//     if (!file) {
//         fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", filename);
//         return -1;
//     }

//     fread(trad_sig_len, sizeof(unsigned int), 1, file);
//     *trad_sig = malloc(*trad_sig_len);
//     fread(*trad_sig, 1, *trad_sig_len, file);
    
//     fread(hybrid_sig_len, sizeof(size_t), 1, file);
//     *hybrid_sig = malloc(*hybrid_sig_len);
//     fread(*hybrid_sig, 1, *hybrid_sig_len, file);

//     fclose(file);
//     return 0;
// }

// int main(int argc, char *argv[]) {
//     if (argc != 4) {
//         fprintf(stderr, "Usage: %s <file> <trad_algo> <hybrid_algo>\n", argv[0]);
//         return 1;
//     }

//     char *file_path = argv[1], *trad_algo = argv[2], *hybrid_algo = argv[3];
//     unsigned char *trad_signature = NULL, *hybrid_signature = NULL;
//     unsigned int trad_sig_len;
//     size_t hybrid_sig_len;
    

//     if (read_signed_file(file_path, &trad_signature, &trad_sig_len, &hybrid_signature, &hybrid_sig_len)) {
//         return 1;
//     }

//     int trad_verify_result = 0, hybrid_verify_result = 0;
    
//     // Vérification de la signature traditionnelle
//     if (strcmp(trad_algo, "DSA") == 0) {
//         DSA *dsa_key=DSA_new(); 
//         trad_verify_result = dsa_verify(dsa_key,file_path,trad_signature, trad_sig_len);
        
//     } else if (strcmp(trad_algo, "RSA") == 0) {
//         RSA *rsa_key= RSA_new(); 
//         trad_verify_result = rsa_verify(rsa_key,file_path,trad_signature, trad_sig_len);
//     } else if (strcmp(trad_algo, "ECDSA") == 0) {
//         EC_KEY *ec_key =EC_KEY_new_by_curve_name(NID_secp256k1); 
//         trad_verify_result = ecdsa_verify(ec_key,file_path,trad_signature, trad_sig_len);
//     } else {
//         fprintf(stderr, "Algorithme traditionnel inconnu : %s\n", trad_algo);
//         return 1;
//     }
    
//     // Vérification de la signature post-quantique
//     if (strcmp(hybrid_algo, "Dilithium") == 0) {
//         uint8_t public_key[CRYPTO_PUBLICKEYBYTES];  
//         const char *message = "Hello, Dilithium!";
//         size_t message_len;
//         hybrid_verify_result = dilithium_verify(hybrid_signature, hybrid_sig_len, message, message_len, public_key);
    
//         // } else if (strcmp(hybrid_algo, "Falcon") == 0) {
//     //     hybrid_verify_result = falcon_verify(hybrid_signature, hybrid_sig_len);
//     } else {
//         fprintf(stderr, "Algorithme hybride inconnu : %s\n", hybrid_algo);
//         return 1;
//     }
    
//     printf("%s : %s\n", trad_algo, trad_verify_result ? "VALIDÉE" : "INVALIDE");
//     printf("%s : %s\n", hybrid_algo, hybrid_verify_result ? "VALIDÉE" : "INVALIDE");
    
//     if (trad_verify_result && hybrid_verify_result) {
//         printf("Signature hybride VALIDÉE !\n");
//     } else {
//         printf("Signature hybride INVALIDE !\n");
//     }
    
//     free(trad_signature);
//     free(hybrid_signature);
//     return 0;
// }
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dsa_signature.h"
#include "rsa_sign.h"
#include "ecdsa_sign.h"
#include "dilithium_signature.h"
#include "dilithium/ref/api.h"

int read_signed_file(const char *filename, unsigned char **trad_sig, unsigned int *trad_sig_len, 
                     unsigned char **hybrid_sig, size_t *hybrid_sig_len, char **trad_algo, char **hybrid_algo) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", filename);
        return -1;
    }

    fread(trad_algo, sizeof(char), 4, file);  // Lire l'algorithme traditionnel
    fread(hybrid_algo, sizeof(char), 8, file);  // Lire l'algorithme hybride
    
    fread(trad_sig_len, sizeof(unsigned int), 1, file);
    *trad_sig = malloc(*trad_sig_len);
    fread(*trad_sig, 1, *trad_sig_len, file);

    fread(hybrid_sig_len, sizeof(size_t), 1, file);
    *hybrid_sig = malloc(*hybrid_sig_len);
    fread(*hybrid_sig, 1, *hybrid_sig_len, file);

    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <signed_file>\n", argv[0]);
        return 1;
    }

    char *file_path = argv[1];
    unsigned char *trad_signature = NULL, *hybrid_signature = NULL;
    unsigned int trad_sig_len;
    size_t hybrid_sig_len;
    char *trad_algo = malloc(4), *hybrid_algo = malloc(8);

    if (read_signed_file(file_path, &trad_signature, &trad_sig_len, &hybrid_signature, &hybrid_sig_len, &trad_algo, &hybrid_algo)) {
        return 1;
    }

    int trad_verify_result = 0, hybrid_verify_result = 0;
    
    // Vérification de la signature traditionnelle
    if (strcmp(trad_algo, "DSA") == 0) {
        DSA *dsa_key = DSA_new();
        trad_verify_result = dsa_verify(dsa_key, file_path, trad_signature, trad_sig_len);
    } else if (strcmp(trad_algo, "RSA") == 0) {
        RSA *rsa_key = RSA_new();
        trad_verify_result = rsa_verify(rsa_key, file_path, trad_signature, trad_sig_len);
    } else if (strcmp(trad_algo, "ECDSA") == 0) {
        EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_secp256k1);
        trad_verify_result = ecdsa_verify(ec_key, file_path, trad_signature, trad_sig_len);
    } else {
        fprintf(stderr, "Algorithme traditionnel inconnu : %s\n", trad_algo);
        return 1;
    }
    
    // Vérification de la signature post-quantique
    if (strcmp(hybrid_algo, "Dilithium") == 0) {
        uint8_t public_key[CRYPTO_PUBLICKEYBYTES];
        const char *message = "Hello, Dilithium!";
        size_t message_len;
        hybrid_verify_result = dilithium_verify(hybrid_signature, hybrid_sig_len, message, message_len, public_key);
    } else {
        fprintf(stderr, "Algorithme hybride inconnu : %s\n", hybrid_algo);
        return 1;
    }

    printf("%s : %s\n", trad_algo, trad_verify_result ? "VALIDÉE" : "INVALIDE");
    printf("%s : %s\n", hybrid_algo, hybrid_verify_result ? "VALIDÉE" : "INVALIDE");

    if (trad_verify_result && hybrid_verify_result) {
        printf("Signature hybride VALIDÉE !\n");
    } else {
        printf("Signature hybride INVALIDE !\n");
    }

    free(trad_signature);
    free(hybrid_signature);
    free(trad_algo);
    free(hybrid_algo);
    return 0;
}
