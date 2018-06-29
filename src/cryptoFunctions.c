/*
 * cryptoFunctions.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */

#include "cryptoFunctions.h"

EVP_PKEY *genX25519KeyPair(void) {
	/* Generate private and public keys */
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL);
	EVP_PKEY_keygen_init(pctx);
	EVP_PKEY_keygen(pctx, &pkey);
	EVP_PKEY_CTX_free(pctx);
	return pkey;
}
