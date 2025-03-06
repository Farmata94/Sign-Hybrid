#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define MESSAGE_MAX_LEN 1024

// Fonction simple de hachage (XOR-based, pour éviter OpenSSL)
void simple_hash(const char *filename, uint8_t *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("❌ Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[MESSAGE_MAX_LEN] = {0};
    size_t bytes_read = fread(buffer, 1, MESSAGE_MAX_LEN, file);
    fclose(file);

    for (size_t i = 0; i < 32; i++) {
        hash[i] = 0;
        for (size_t j = 0; j < bytes_read; j++) {
            hash[i] ^= buffer[j];  // XOR simple
        }
    }
}

size_t read_file(const char *filename, uint8_t *buffer, size_t buffer_size) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("❌ Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }

    size_t bytes_read = fread(buffer, 1, buffer_size, file);
    fclose(file);
    return bytes_read;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("❌ Usage: %s <fichier_original> <signature>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *message_file = argv[1];
    const char *signature_file = argv[2];

    uint8_t hash[32];
    simple_hash(message_file, hash);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256f_simple);
    if (sig == NULL) {
        fprintf(stderr, "❌ Erreur: PHINICS+ indisponible.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    FILE *pk_file = fopen("public_key.bin", "rb");
    if (!pk_file) {
        fprintf(stderr, "❌ Erreur : Impossible d'ouvrir public_key.bin !\n");
        return EXIT_FAILURE;
    }
    fread(public_key, 1, sig->length_public_key, pk_file);
    fclose(pk_file);
    printf("✅ Clé publique chargée avec succès.\n");

    uint8_t *signature = malloc(sig->length_signature);
    read_file(signature_file, signature, sig->length_signature);

    OQS_STATUS verification = OQS_SIG_verify(sig, hash, sizeof(hash), signature, sig->length_signature, public_key);
    if (verification == OQS_SUCCESS) {
        printf("✅ Signature valide !\n");
    } else {
        printf("❌ Signature invalide !\n");
    }

    OQS_SIG_free(sig);
    free(public_key);
    free(signature);

    return verification == OQS_SUCCESS ? EXIT_SUCCESS : EXIT_FAILURE;
}
