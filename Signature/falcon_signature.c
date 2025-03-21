#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "liboqs/build/include/oqs/oqs.h"

#ifdef _WIN32
    #include <windows.h>
    #define snprintf _snprintf // Windows utilise _snprintf
#else
    #include <unistd.h>
#endif

#define SIG_SIZE 1024  // Taille de la signature (Falcon-512)

// Fonction pour lire un fichier
size_t read_file(const char *filename, uint8_t **buffer) {
    printf("Lecture du fichier %s...\n", filename);
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Erreur : Impossible d'ouvrir le fichier %s\n", filename);
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    rewind(file);
    
    *buffer = malloc(filesize);
    if (!(*buffer)) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        fclose(file);
        return 0;
    }
    fread(*buffer, 1, filesize, file);
    fclose(file);
    return filesize;
}

// Fonction de signature
int sign_document(const char *input_file, const char *signature_file) {
    uint8_t *message = NULL;
    size_t message_len = read_file(input_file, &message);
    if (message_len == 0) return 1;
    
    printf("Initialisation de Falcon...\n");
    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!sig) {
        fprintf(stderr, "Erreur : Impossible d'initialiser Falcon\n");
        free(message);
        return 1;
    }
    
    printf("Allocation de la mémoire pour les clés...\n");
    uint8_t *sk = malloc(sig->length_secret_key);
    uint8_t *pk = malloc(sig->length_public_key);
    uint8_t signature[SIG_SIZE];
    size_t sig_len = SIG_SIZE;
    
    if (!sk || !pk) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        OQS_SIG_free(sig);
        free(message);
        return 1;
    }
    
    printf("Génération des clés...\n");
    if (OQS_SIG_keypair(sig, pk, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur lors de la génération des clés\n");
        OQS_SIG_free(sig);
        free(message);
        free(sk);
        free(pk);
        return 1;
    }
    printf("Clés générées avec succès!\n");
    
    printf("Signature en cours...\n");
    if (OQS_SIG_sign(sig, signature, &sig_len, message, message_len, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur : La signature a échoué\n");
        OQS_SIG_free(sig);
        free(message);
        free(sk);
        free(pk);
        return 1;
    }
    printf("Signature réussie ! Taille de la signature : %zu octets\n", sig_len);
    
    FILE *sig_file = fopen(signature_file, "wb");
    if (!sig_file) {
        fprintf(stderr, "Erreur : Impossible de sauvegarder la signature\n");
        OQS_SIG_free(sig);
        free(message);
        free(sk);
        free(pk);
        return 1;
    }
    size_t written = fwrite(signature, 1, sig_len, sig_file);
    if (written != sig_len) {
        fprintf(stderr, "Erreur : La signature n'a pas été entièrement écrite (%zu/%zu octets)\n", written, sig_len);
    }
    fclose(sig_file);
    
    printf("Signature enregistrée dans %s\n", signature_file);
    
    OQS_SIG_free(sig);
    free(message);
    free(sk);
    free(pk);
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage : %s <fichier à signer> <fichier de signature>\n", argv[0]);
        return 1;
    }
    return sign_document(argv[1], argv[2]);
}