#ifndef RSA_SIGN_H  // Protection contre l'inclusion multiple
#define RSA_SIGN_H

#include <openssl/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>    // Pour SHA256
#include <openssl/err.h>    // Pour gérer les erreurs OpenSSL
#include <openssl/pem.h>    // Pour écrire/charger les clés au format PEM


int rsa_sign();  // Déclaration de la fonction
int rsa_verify(RSA *rsa, const char *message, unsigned char *signature, unsigned int sig_len);

#endif
