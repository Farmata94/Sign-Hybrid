#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium/ref/api.h"  // Inclut l'API de l'implémentation de référence
#include "dilithium/ref/params.h"
#include "dilithium_signature.h"


int dilithium_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key) {
    const uint8_t *ctx = NULL;  // Pas de contexte utilisé
    size_t ctxlen = 0;

    if (pqcrystals_dilithium2_ref_verify(signature, signature_len, message, message_len, ctx, ctxlen, public_key) != 0) {
        fprintf(stderr, "Signature invalide\n");
        return 1;
    }

    printf("Signature valide !\n");
    return 0;
}
