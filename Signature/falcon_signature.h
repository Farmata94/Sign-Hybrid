#ifndef Falcon_SIGN_H  // Protection contre l'inclusion multiple
#define Falcon_SIGN_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "PQClean/crypto_sign/falcon-512/clean/api.h"  


int generate_falcon_keypair(uint8_t **public_key, size_t *public_key_len, uint8_t **secret_key, size_t *secret_key_len);
int falcon_sign(const uint8_t *message, size_t message_len, uint8_t **signature, size_t *signature_len, const uint8_t *secret_key, size_t secret_key_len) ;
int falcon_verify(const uint8_t *signature, size_t signature_len, const uint8_t *message, size_t message_len, const uint8_t *public_key, size_t public_key_len);

void benchmark_falcon();

#endif
