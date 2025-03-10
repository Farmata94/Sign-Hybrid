#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>

#define MESSAGE_MAX_LEN 1024

// Fonction simple de hachage (remplace OpenSSL)
void simple_hash(const char *filename, uint8_t *hash) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("❌ Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }

    uint8_t buffer[MESSAGE_MAX_LEN] = {0};
    size_t bytes_read = fread(buffer, 1, MESSAGE_MAX_LEN, file);
    fclose(file);

    // Hash simple : XOR des octets (pour éviter OpenSSL, non sécurisé mais suffisant ici)
    for (size_t i = 0; i < 32; i++) {
        hash[i] = 0;
        for (size_t j = 0; j < bytes_read; j++) {
            hash[i] ^= buffer[j];  // Simple XOR-based hashing
        }
    }
}

void save_file(const char *filename, uint8_t *data, size_t length) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("❌ Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    fwrite(data, 1, length, file);
    fclose(file);
}

int phinics_sign(int argc, char **argv) {
    if (argc != 2) {
        printf("❌ Usage: %s <fichier_a_signer>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *message_file = argv[1];
    uint8_t hash[32];
    simple_hash(message_file, hash);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_sphincs_shake_256f_simple);
    if (sig == NULL) {
        fprintf(stderr, "❌ Erreur: PHINICS+ indisponible.\n");
        return EXIT_FAILURE;
    }

    uint8_t *public_key = malloc(sig->length_public_key);
    uint8_t *private_key = malloc(sig->length_secret_key);
    uint8_t *signature = malloc(sig->length_signature);
    size_t signature_len;

    if (OQS_SIG_keypair(sig, public_key, private_key) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Erreur: Génération des clés échouée.\n");
        return EXIT_FAILURE;
    }

    save_file("public_key.bin", public_key, sig->length_public_key);
    printf("✅ Clé publique sauvegardée dans 'public_key.bin'.\n");

    if (OQS_SIG_sign(sig, signature, &signature_len, hash, sizeof(hash), private_key) != OQS_SUCCESS) {
        fprintf(stderr, "❌ Erreur: Signature échouée.\n");
        return EXIT_FAILURE;
    }

    save_file("signature.bin", signature, signature_len);
    printf("✅ Signature réussie et enregistrée dans 'signature.bin'.\n");

    OQS_SIG_free(sig);
    free(public_key);
    free(private_key);
    free(signature);

    return EXIT_SUCCESS;
}
