#ifndef ECDSA_SIGN_H
#define ECDSA_SIGN_H

#include <openssl/ecdsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>    // Pour SHA256
#include <openssl/err.h>    // Pour gérer les erreurs OpenSSL
#include <openssl/pem.h>    // Pour écrire/charger les clés au format PEM

int ecdsa_sign();  // Déclaration correcte

#endif
