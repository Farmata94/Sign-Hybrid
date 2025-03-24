#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dsa_signature.h"
#include "rsa_sign.h"
#include "ecdsa_sign.h"
#include "dilithium_signature.h"
#include "dilithium/ref/api.h"
#include "dilithium/ref/params.h"

// Fonction pour lire un fichier
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
    if (!*buffer) {
        fprintf(stderr, "Erreur : allocation mémoire\n");
        fclose(file);
        return -1;
    }

    fread(*buffer, 1, *length, file);
    fclose(file);
    return 0;
}

// Fonction de vérification hybride
int verify_hybrid(const char *signature_file, const char *trad_algo, const char *hybrid_algo) {
    FILE *sig_file = fopen(signature_file, "rb");
    if (!sig_file) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", signature_file);
        return 1;
    }

    // Lire les signatures depuis le fichier
    unsigned int trad_sig_len;
    uint32_t hybrid_sig_len_32;
    size_t hybrid_sig_len;
    unsigned char *trad_signature, *hybrid_signature;

    fread(&trad_sig_len, sizeof(uint32_t), 1, sig_file);
    trad_signature = malloc(trad_sig_len);
    fread(trad_signature, 1, trad_sig_len, sig_file);

    fread(&hybrid_sig_len_32, sizeof(uint32_t), 1, sig_file);
    hybrid_sig_len = (size_t)hybrid_sig_len_32;
    hybrid_signature = malloc(hybrid_sig_len);
    fread(hybrid_signature, 1, hybrid_sig_len, sig_file);

    fclose(sig_file);

    // Lire le message à partir du fichier original
    unsigned char *message;
    size_t message_len;
    if (read_file(signature_file, &message, &message_len)) {
        free(trad_signature);
        free(hybrid_signature);
        return 1;
    }

    int trad_valid = 0, hybrid_valid = 0;

    // Déclaration des clés
    DSA *dsa = NULL;
    RSA *rsa = NULL;
    EC_KEY *ec_key = NULL;
    uint8_t public_key[CRYPTO_PUBLICKEYBYTES];


    // Vérification de la signature traditionnelle
    if (dsa && strcmp(trad_algo, "DSA") == 0) {
        trad_valid = dsa_verify(dsa, trad_signature, trad_sig_len);
    } else if (rsa && strcmp(trad_algo, "RSA") == 0) {
        trad_valid = rsa_verify(rsa, trad_signature, trad_sig_len);
    } else if (ec_key && strcmp(trad_algo, "ECDSA") == 0) {
        trad_valid = ecdsa_verify(ec_key, (const char *)message, trad_signature, trad_sig_len);
    }

    // Vérification de la signature post-quantique
    if (strcmp(hybrid_algo, "Dilithium") == 0) {
        hybrid_valid = dilithium_verify( hybrid_signature,hybrid_sig_len,message, message_len,public_key );
        

    }

    // Résultat
    if (trad_valid && hybrid_valid) {
        printf("✅ Signature hybride valide !\n");
    } else {
        printf("❌ Signature invalide !\n");
    }

    // Libérer la mémoire allouée
    free(message);
    free(trad_signature);
    free(hybrid_signature);

    // Libérer les clés
    if (dsa) DSA_free(dsa);
    if (rsa) RSA_free(rsa);
    if (ec_key) EC_KEY_free(ec_key);

    return !(trad_valid && hybrid_valid);
}

// Fonction principale
int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <signature_file> <trad_algo> <hybrid_algo> \n", argv[0]);
        return 1;
    }

    char  *signature_file = argv[1],*trad_algo = argv[2], *hybrid_algo = argv[3];
    
    printf("🔍 Vérification du fichier en cours...\n");
    return verify_hybrid(signature_file, trad_algo, hybrid_algo);
}
