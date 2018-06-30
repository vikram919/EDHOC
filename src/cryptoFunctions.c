/*
 * cryptoFunctions.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */

#include "cryptoFunctions.h"

EVP_PKEY *gen_x25519() {

	int nid = 710;
	EVP_PKEY_CTX *pctx1, *kctx1;
	EVP_PKEY *params1, *pkey1 = NULL;
	const char *name = OBJ_nid2sn(nid);
	if (name == NULL) {
		fprintf(stderr, "No such EC curve.\n");
		return 1;
	}

	/* Create the context for parameter generation */
	pctx1 = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
	if (!pctx1)
		fprintf(stderr, "context failed\n");
	if (EVP_PKEY_paramgen_init(pctx1) <= 0)
		fprintf(stderr, "param init failed\n");
	if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx1, nid) <= 0)
		fprintf(stderr, "param init curve nid failed\n");
	if (EVP_PKEY_paramgen(pctx1, &params1) <= 0)
		fprintf(stderr, "param gen curve nid failed\n");

	/* Create the context for the key generation */
	kctx1 = EVP_PKEY_CTX_new(params1, NULL);
	if (EVP_PKEY_keygen_init(kctx1) <= 0)
		fprintf(stderr, "keygen init failed\n");
	if (EVP_PKEY_keygen(kctx1, &pkey1) <= 0) {
		fprintf(stderr, "EVP_PKEY_keygen error.\n");
	}
	PEM_write_PrivateKey(stdout, pkey1, NULL, NULL, 0, NULL, NULL);
	PEM_write_PUBKEY(stdout, pkey1);

	/* X25519 */

	EC_GROUP *ec_group;
	ec_group = EC_GROUP_new_by_curve_name(NID_X25519);
	if (ec_group == NULL) {
		printf("\nEC_GROUP is INVALID.\n");
	} else {
		printf("\nEC_GROUP is ok.\n");
	}

	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx;
	if (NULL == (pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL))) {
		fprintf(stderr, "error while initializing public key context\n");
	}
	if (EVP_PKEY_keygen_init(pctx) <= 0) {
		printf("error while initialization %d\n");
	}
	if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
		printf("error while key generation\n");
	}
	EVP_PKEY_CTX_free(pctx);
	/* Print keys to stdout */
	printf("\nBob's PRIVATE KEY:\n");
	PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
	return pkey;
}

