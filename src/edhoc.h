#include "cbor.h"
#include "define.h"
#include "cryptoFunctions.h"
#include <openssl/evp.h>


unsigned char *gen_msg1_sym(unsigned char *app_1, size_t app_1_sz, EVP_PKEY *pkey,
		const char *filepath);
void *parseEdhocSymMsg1(cbor_item_t *MSG);

size_t message_1_len;
unsigned char *message_1;
