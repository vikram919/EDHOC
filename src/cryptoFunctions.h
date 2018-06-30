/*
 * cryptoFunctions.h
 *
 *  Created on: Jun 28, 2018
 *      Author: vikram
 */
#include "cbor.h"
#include "define.h"
#include "enum.h"
#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/ocsp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <sodium.h>


EVP_PKEY *gen_x25519();
void gen_random(unsigned char *buf, size_t length);
int gen_sodium_pub_key(unsigned char *pub_key, const unsigned char *priv_key);
void computeSharedSecret(void);
unsigned char *computeHash(unsigned char *message);
EVP_PKEY getPubKey();
EVP_PKEY getPrivKey();
