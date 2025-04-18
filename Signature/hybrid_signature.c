#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dsa_signature.h"
#include "rsa_sign.h"
#include "ecdsa_sign.h"
#include "falcon_signature.h"
#include "dilithium_signature.h" 
#include "dilithium/ref/api.h"
#include "dilithium/ref/params.h"
#include "liboqs/build/include/oqs/oqs.h"

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
    size_t bytesRead = fread(*buffer, 1, *length, file);
    if (bytesRead != *length) {
        fprintf(stderr, "Erreur : lecture incomplète de %s\n", filename);
        free(*buffer);
        fclose(file);
        return -1;
    }
    fclose(file);
    return 0;    
}

// Fonction de signature hybride
int sign_hybrid(const char *file_path, const char *trad_algo, const char *hybrid_algo, const char *output_file) {
    unsigned char *message, *trad_signature = NULL, *hybrid_signature = NULL;
    size_t message_len, hybrid_sig_len;
    unsigned int trad_sig_len;

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
        fprintf(stderr, "Algorithme traditionnel unknown : %s\n", trad_algo);
        free(message);
        return 1;
    }

    // Signature post-quantique
    if (strcmp(hybrid_algo, "Dilithium") == 0) {
        benchmark_dilithium(message, message_len, &hybrid_signature, &hybrid_sig_len);
    }else if (strcmp(hybrid_algo, "Falcon") == 0) {
        benchmark_falcon(message, message_len, &hybrid_signature, &hybrid_sig_len);
    } else {
        fprintf(stderr, "Algorithme hybrid unknown : %s\n", hybrid_algo);
        free(message);
        free(trad_signature);
        return 1;
    }

    double total_time = (double)(clock() - start_total) / CLOCKS_PER_SEC;

    // Écriture des signatures dans le fichier
    FILE *out = fopen(output_file, "wb");
    if (!out) {
        fprintf(stderr, "Error: unable to open %s in writing\n", output_file);
        free(message);
        free(trad_signature);
        free(hybrid_signature);
        return 1;
    }

    uint32_t hybrid_sig_len_32 = (uint32_t)hybrid_sig_len;
    fwrite(&trad_sig_len, sizeof(uint32_t), 1, out);
    fwrite(trad_signature, 1, trad_sig_len, out);
    fwrite(&hybrid_sig_len_32, sizeof(uint32_t), 1, out);
    fwrite(hybrid_signature, 1, hybrid_sig_len, out);

    printf("✅ Succès : trad=%u, hybrid=%zu\n", trad_sig_len, hybrid_sig_len);
    printf("⏱️ Total time : %.6f sec\n", total_time);


    fclose(out);
    free(message);
    free(trad_signature);
    free(hybrid_signature);
    
    return 0;
}

// Fonction principale
int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "Usage: %s <file> <trad_algo> <hybrid_algo> <signature_file>\n", argv[0]);
        return 1;
    }

    char *file_path = argv[1], *trad_algo = argv[2], *hybrid_algo = argv[3], *signature_file = argv[4];
    
    printf("🔐 Signing the current file...\n");
    return sign_hybrid(file_path, trad_algo, hybrid_algo, signature_file);
}
