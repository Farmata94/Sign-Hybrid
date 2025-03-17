#ifndef Dilithium_SIGN_H  // Protection contre l'inclusion multiple
#define Dilithium_SIGN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dilithium/ref/api.h" // Pour Dilithium
#include "dilithium/ref/params.h"

void generate_dilithium_keypair();
int dilithium_sign();
int dilithium_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key);
void benchmark_dilithium();

#endif
