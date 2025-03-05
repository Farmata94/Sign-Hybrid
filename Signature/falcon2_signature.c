#ifndef PQCLEAN_FALCON512_CLEAN_API_H
#define PQCLEAN_FALCON512_CLEAN_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "randombytes.h"
#include "sha2.h"
#include "falcon.h"

#define PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES   1281
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES   897
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES            666
#define PQCLEAN_FALCON512_CLEAN_CRYPTO_ALGNAME          "Falcon-512"

int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
    uint8_t *pk, uint8_t *sk) {
    uint8_t seed[48];
    randombytes(seed, sizeof(seed));
    return falcon_keygen_make(sk, PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES, pk, PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES, seed, sizeof(seed));
}

int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen, const uint8_t *sk) {
    return falcon_sign_dyn(sig, siglen, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES, sk, m, mlen);
}

int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen, const uint8_t *pk) {
    return falcon_verify(sig, siglen, m, mlen, pk);
}

void sign_file(const char *filename, const uint8_t *sk) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    rewind(file);
    uint8_t *message = malloc(filesize);
    fread(message, 1, filesize, file);
    fclose(file);
    uint8_t signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
    size_t siglen;
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(signature, &siglen, message, filesize, sk) != 0) {
        fprintf(stderr, "Erreur lors de la signature du fichier\n");
        free(message);
        exit(EXIT_FAILURE);
    }
    file = fopen("signature.bin", "wb");
    fwrite(signature, 1, siglen, file);
    fclose(file);
    printf("Signature enregistrée dans signature.bin\n");
    free(message);
}

void verify_file(const char *filename, const char *sigfile, const uint8_t *pk) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Erreur ouverture fichier");
        exit(EXIT_FAILURE);
    }
    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    rewind(file);
    uint8_t *message = malloc(filesize);
    fread(message, 1, filesize, file);
    fclose(file);
    FILE *sig = fopen(sigfile, "rb");
    if (!sig) {
        perror("Erreur ouverture fichier signature");
        free(message);
        exit(EXIT_FAILURE);
    }
    uint8_t signature[PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES];
    fread(signature, 1, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES, sig);
    fclose(sig);
    if (PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(signature, PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES, message, filesize, pk) == 0) {
        printf("Signature valide !\n");
    } else {
        printf("Signature invalide !\n");
    }
    free(message);
}

int main() {
    uint8_t pk[PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES];
    PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk, sk);
    printf("Clés générées\n");
    sign_file("document.txt", sk);
    verify_file("document.txt", "signature.bin", pk);
    return 0;
}

#endif
