/*
 * edhocClient.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */
#include <stdio.h>
#include <stdio.h>
#include "cryptoFunctions.h"

int main(void) {
	/* Generate private and public keys */
	EVP_PKEY *pkey = genX25519KeyPair();
	printf("\nBob's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, pkey);
	return 0;
}

