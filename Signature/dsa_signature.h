#ifndef DSA_SIGN_H  // Protection contre l'inclusion multiple
#define DSA_SIGN_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dsa.h>    // Pour DSA et fonctions associées
#include <openssl/sha.h>    // Pour SHA256
#include <openssl/err.h>    // Pour gérer les erreurs OpenSSL
#include <openssl/pem.h>    // Pour écrire/charger les clés au format PEM

int dsa_sign();  // Déclaration de la fonction
int dsa_verify(DSA *dsa, const char *message, unsigned char *signature, unsigned int sig_len);

#endif
