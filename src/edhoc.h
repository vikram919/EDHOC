#include "cbor.h"
#include "define.h"
#include "cryptoFunctions.h"
#include <openssl/evp.h>

unsigned char *gen_msg1_sym(unsigned char *pkey);
void *parse_edhoc_sym_msg1(cbor_item_t *MSG);
void *print_cbor_bytestring_to_stdout(unsigned char *buffer, size_t length);
void *print_cbor_bytestring_to_stdout_hex(unsigned char *buffer, size_t length);
void *print_cbor_array_to_stdout(unsigned char *buffer, size_t length);

size_t message_1_len;
unsigned char *message_1;
