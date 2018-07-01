/*
 * edhocClient.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */

#include "cryptoFunctions.h"
#include "edhoc.h"
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

const int S_KEY_LENGTH = 32;

int main(void)
{
	unsigned char alice_priv[S_KEY_LENGTH];
	unsigned char alice_pub[S_KEY_LENGTH];
	if (sodium_init() < 0) {
		fprintf(stderr, "calling sodium lib failed %d\n", sodium_init());
	} else {
		printf("sodium lib call successfull\n");
	}
	/* Generate private and public keys */
	gen_random(alice_priv, S_KEY_LENGTH);
	gen_sodium_pub_key(alice_pub, alice_priv);
	printf("size of %ld\n", sizeof(alice_pub));

	/*Generate message1 */
	unsigned char *alice_msg1 = gen_msg1_sym(alice_pub);

	return 0;
}

