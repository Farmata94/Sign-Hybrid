#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dsa_signature.h"
#include "rsa_sign.h"
#include "ecdsa_sign.h"
#include "dilithium_signature.h"
#include "dilithium/ref/api.h" // Pour Dilithium
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
    fread(*buffer, 1, *length, file);
    fclose(file);
    return 0;
}

// Function verify

int verify_hybrid_signature(const char *signature_file, const char *trad_algo, const char *hybrid_algo) {
    unsigned char *message;
    size_t message_len;

    // Lire le fichier du message
    if (read_file(signature_file, &message, &message_len)) return 1;

    // Lire les signatures du fichier
    FILE *sig_file = fopen(signature_file, "rb");
    if (!sig_file) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s\n", signature_file);
        free(message);
        return 1;
    }

    unsigned int trad_sig_len;
    size_t hybrid_sig_len;
    unsigned char *trad_signature, *hybrid_signature;

   ;

    // Après lecture des signatures
    uint32_t hybrid_sig_len_32;
    fread(&trad_sig_len, sizeof(uint32_t), 1, sig_file);
    trad_signature = malloc(trad_sig_len);
    fread(trad_signature, 1, trad_sig_len, sig_file);
    
    fread(&hybrid_sig_len_32, sizeof(uint32_t), 1, sig_file);
    hybrid_sig_len = (size_t) hybrid_sig_len_32;  // Conversion propre
    hybrid_signature = malloc(hybrid_sig_len);
    fread(hybrid_signature, 1, hybrid_sig_len, sig_file);
    



    fclose(sig_file);

    int trad_valid = 0, hybrid_valid = 0;
    

    // Affichage du résultat
    if (trad_valid && hybrid_valid) {
        printf("✅ Signature hybride valide !\n");
    } else {
        printf("❌ Signature invalide !\n");
    }
   
    free(message);
    free(trad_signature);
    free(hybrid_signature);

    return !(trad_valid && hybrid_valid);  // Retourne 0 si tout est valide, sinon 1
}

int sign_hybrid(const char *file_path, const char *trad_algo, const char *hybrid_algo, const char *output_file) {
    unsigned char *message, *trad_signature = NULL, *hybrid_signature = NULL;
    size_t message_len, hybrid_sig_len;
    unsigned int trad_sig_len;
    double total_time = 0;

    // Lire le fichier d'entrée
    if (read_file(file_path, &message, &message_len)) {
        return 1;
    }
    clock_t start_total = clock();
    // Signature traditionnelle
    if (strcmp(trad_algo, "DSA") == 0) {
        benchmark_dsa(message, message_len, &trad_signature, &trad_sig_len);
    } else if (strcmp(trad_algo, "RSA") == 0) {
        benchmark_rsa(message, message_len, &trad_signature, &trad_sig_len);
    } else if (strcmp(trad_algo, "ECDSA") == 0) {
        benchmark_ecdsa(message, message_len, &trad_signature, &trad_sig_len);
    } else {
        fprintf(stderr, "Algorithme traditionnel inconnu : %s\n", trad_algo);
        free(message);
        return 1;
    }

    // Signature post-quantique
    if (strcmp(hybrid_algo, "Dilithium") == 0) {
        benchmark_dilithium(message, message_len, &hybrid_signature, &hybrid_sig_len);
    } else {
        fprintf(stderr, "Algorithme hybride inconnu : %s\n", hybrid_algo);
        free(message);
        free(trad_signature);
        return 1;
    }
    total_time = (double)(clock() - start_total) / CLOCKS_PER_SEC;

    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Erreur : impossible d'ouvrir %s en écriture\n", output_file);
        free(message);
        free(trad_signature);
        free(hybrid_signature);
        return 1;
    }
    
    uint32_t hybrid_sig_len_32 = (uint32_t) hybrid_sig_len;
    fwrite(&trad_sig_len, sizeof(uint32_t), 1, out);
    fwrite(trad_signature, 1, trad_sig_len, out);
    fwrite(&hybrid_sig_len_32, sizeof(uint32_t), 1, out);  // Taille de la signature hybride
    fwrite(hybrid_signature, 1, hybrid_sig_len, out);

    printf("Écriture des tailles : trad=%u, hybrid=%zu\n", trad_sig_len, hybrid_sig_len);
    


    printf("Hybride sign: %.6f\n", total_time);
   

    free(message);
    free(trad_signature);
    free(hybrid_signature);
    return 0;
}


// Fonction principale
int main(int argc, char *argv[]) {
    
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <file> <trad_algo> <hybrid_algo> <signature_file> <mode>\n", argv[0]);
        return 1;
    }

    char *file_path = argv[1], *trad_algo = argv[2], *hybrid_algo = argv[3], *signature_file = argv[4], *mode = argv[5];

    if (strcmp(mode, "sign") == 0) {
        printf(" Signature du fichier en cours...\n");
        return sign_hybrid(file_path, trad_algo, hybrid_algo, signature_file);
    } else if (strcmp(mode, "verify") == 0) {
        printf("Vérification de la signature...\n");
        return verify_hybrid_signature(signature_file, trad_algo, hybrid_algo );
    } else {
        fprintf(stderr, "Mode inconnu : %s (utilise 'sign' ou 'verify')\n", mode);
        return 1;
    }

    return 0;
}
