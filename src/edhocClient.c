/*
 * edhocClient.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */

#include "cryptoFunctions.h"
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

int main(void) {

	/* Generate private and public keys */
	EVP_PKEY *session_pkey = gen_x25519();
	printf("\nAlice's PUBKEY:\n");
	PEM_write_PUBKEY(stdout, session_pkey);

//	PEM_write_PrivateKey(stdout, session_pkey, NULL, NULL, 0, NULL, NULL);
//	if(!PEM_write_PrivateKey(stdout, session_pkey, NULL, NULL, 0, NULL, NULL)){
//		printf("failed");
//	}
//
//	FILE *keyfile_pu = fopen("./inputparameters/server_PUBKEY.txt", "w");
//	FILE *keyfile_pr = fopen("./inputparameters/server_PrivateKey.txt", "w");

//	/* Write keys to files */
//	PEM_write_EC_PUBKEY(keyfile_pu, session_pkey);
//	PEM_write_ECPrivateKey(keyfile_pr, session_pkey, NULL, NULL, 0, NULL, NULL);
//
//	/* Read Alice's public key */
//	EVP_PKEY *peerkey = NULL;
//	peerkey = PEM_read_PUBKEY(keyfile_pu, NULL, NULL, NULL);
//	printf("\nAlice's PUBKEY:\n");
//	PEM_write_PUBKEY(stdout, peerkey);
//
//	fclose(keyfile_pu);
//	fclose(keyfile_pr);
//
//	/*check cose working properly*/
//	printf("cose enum value: %d\n", COSE_sign_object);
	return 0;
}

