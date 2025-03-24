#ifndef Falcon_SIGN_H  // Protection contre l'inclusion multiple
#define Falcon_SIGN_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "liboqs/build/include/oqs/oqs.h"
#include "liboqs/build/include/oqs/sig_falcon.h"  // bibliothèque Falcon (libpqcrypto)


int falcon_setup(uint8_t **pk, uint8_t **sk, OQS_SIG **sig);
int falcon_sign(OQS_SIG *sig, uint8_t *sk, uint8_t *message, size_t message_len, uint8_t *signature, size_t *sig_len);
int falcon_verify(OQS_SIG *sig, uint8_t *pk, uint8_t *message, size_t message_len, uint8_t *signature, size_t sig_len);



#endif
