/*
 * edhocClient.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */
#include <stdio.h>
#include <stdio.h>
#include "cryptoFunctions.h"
#include <cose-c/cose.h>

int main(void) {
	/* Generate private and public keys */
	EVP_PKEY *pkey = genX25519KeyPair();
	printf("\nAlice's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, pkey);

	/* Write public key to file */
	BIO *out;
	out = BIO_new_file("../inputparameters/server_PUBKEY.txt", "w+");

	if (!out) {
		/* Error */
		printf("BIO out is empty\n");
	}
	PEM_write_bio_PUBKEY(out, pkey);
	BIO_flush(out);

	/* Read Alice's public key */
	FILE *keyfile = fopen("../inputparameters/server_PUBKEY.txt", "r");
	EVP_PKEY *peerkey = NULL;
	peerkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
	printf("\nAlice's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, peerkey);

	/*check cose working properly*/
	printf("cose enum value: %d\n", COSE_sign_object);
	return 0;
}

