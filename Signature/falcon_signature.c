#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "liboqs/build/include/oqs/oqs.h"

#define SIG_SIZE 1024  // Taille de la signature (Falcon-512)

// Fonction pour générer les clés
int falcon_setup(uint8_t **pk, uint8_t **sk, OQS_SIG **sig) {
    *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (!(*sig)) {
        fprintf(stderr, "Erreur : Impossible d'initialiser Falcon\n");
        return 1;
    }

    *pk = malloc((*sig)->length_public_key);
    *sk = malloc((*sig)->length_secret_key);
    if (!(*pk) || !(*sk)) {
        fprintf(stderr, "Erreur d'allocation mémoire\n");
        return 1;
    }

    if (OQS_SIG_keypair(*sig, *pk, *sk) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur lors de la génération des clés\n");
        return 1;
    }
    return 0;
}

// Fonction pour signer un message
int falcon_sign(OQS_SIG *sig, uint8_t *sk, uint8_t *message, size_t message_len, uint8_t *signature, size_t *sig_len) {
    if (OQS_SIG_sign(sig, signature, sig_len, message, message_len, sk) != OQS_SUCCESS) {
        fprintf(stderr, "Erreur : La signature a échoué\n");
        return 1;
    }
    return 0;
}

// Fonction pour vérifier une signature
int falcon_verify(OQS_SIG *sig, uint8_t *pk, uint8_t *message, size_t message_len, uint8_t *signature, size_t sig_len) {
    if (OQS_SIG_verify(sig, message, message_len, signature, sig_len, pk) != OQS_SUCCESS) {
        printf("Signature invalide !\n");
        return 1;
    }
    printf("Signature valide !\n");
    return 0;
}

int main() {
    clock_t start, end;
    double time_gen_keys, time_sign, time_verify;

    OQS_SIG *sig;
    uint8_t *pk, *sk;
    uint8_t message[] = "Test message for Falcon-512 signature.";
    size_t message_len = strlen((char *)message);
    uint8_t signature[SIG_SIZE];
    size_t sig_len = SIG_SIZE;

    // Mesure du temps de génération des clés
    start = clock();
    if (falcon_setup(&pk, &sk, &sig) != 0) {
        return 1;
    }
    end = clock();
    time_gen_keys = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Falcon Setup : %.2f ms\n", time_gen_keys);

    // Mesure du temps de signature
    start = clock();
    if (falcon_sign(sig, sk, message, message_len, signature, &sig_len) != 0) {
        return 1;
    }
    end = clock();
    time_sign = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Falcon Sign : %.2f ms\n", time_sign);

    // Mesure du temps de vérification
    start = clock();
    if (falcon_verify(sig, pk, message, message_len, signature, sig_len) != 0) {
        return 1;
    }
    end = clock();
    time_verify = ((double)(end - start)) / CLOCKS_PER_SEC * 1000;
    printf("Falcon Verify : %.2f ms\n", time_verify);

    // Libération de la mémoire
    OQS_SIG_free(sig);
    free(pk);
    free(sk);

    return 0;
}
