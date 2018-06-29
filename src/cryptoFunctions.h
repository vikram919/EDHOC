/*
 * cryptoFunctions.h
 *
 *  Created on: Jun 28, 2018
 *      Author: vikram
 */
#include "cbor.h"
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>

EVP_PKEY *genX25519KeyPair(void);
void computeSharedSecret(void);
unsigned char *computeHash(unsigned char *message);
EVP_PKEY getPubKey();
EVP_PKEY getPrivKey();
