/*
 * EdhocMessage1.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */
#include "edhoc.h"
/* unsecured message sent by the device in message1*/
unsigned char app_1[] = "Hello, my name is EDHOC!";

/**
 *This method constructs the EDHOC Message 1.
 *
 *@see: https://tools.ietf.org/html/draft-selander-ace-cose-ecdhe-08#section-5.2
 */
unsigned char *gen_msg1_sym(unsigned char *app_1, size_t app_1_sz, EVP_PKEY *pkey,
		const char *filepath) {

	int msg_type = EDHOC_SYM_MSG_1;
	printf("\n#### GENERATING EDHOC SYMMETRIC MSG_%d ####\n",
			get_msg_num(msg_type));

	cbor_item_t *MSG = cbor_new_indefinite_array();
	if (!CBOR_ITEM_T_init(MSG)) {
		printf("\ncbor_item_t initialization FAILED.\n");
	}

	cbor_item_t *MSG_TYPE = cbor_new_int8();
	MSG_TYPE = cbor_build_uint8(msg_type);
	if (!cbor_array_push(MSG, MSG_TYPE)) {
		printf("\ncbor_array_push MSG_TYPE FAILED.\n");
	}

	cbor_item_t *S_U = cbor_new_definite_bytestring();
	size_t variable_length = rand()
			% (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
	unsigned char *bstr_s_u = gen_random_S_ID(variable_length);
	S_U = cbor_build_bytestring(bstr_s_u, variable_length);
	if (!cbor_array_push(MSG, S_U)) {
		printf("\ncbor_array_push S_U FAILED.\n");
	}

	cbor_item_t *N_U = cbor_new_definite_bytestring();
	ASN1_INTEGER *nonce_asn1 = create_nonce(NONCE_size_bits);
	BIGNUM *bn = ASN1_INTEGER_to_BN(nonce_asn1, NULL);
	unsigned char *bstr_n_u = (unsigned char*) BN_bn2hex(bn);
	N_U = cbor_build_bytestring(bstr_n_u, NONCE_size_bytes);
	if (!cbor_array_push(MSG, N_U)) {
		printf("\ncbor_array_push N_U FAILED.\n");
	}

	/* cbor map format */
	cbor_item_t *E_U = cbor_new_definite_map(E_U_map_size);
	int *bstr_e_u_sz = malloc(sizeof(int));
	unsigned char *bstr_e_u = strip_pkey(pkey, bstr_e_u_sz);
	/* key_1 and key_2 refer to cbor map keys */
	cbor_item_t *key_1;
	key_1 = cbor_new_int8();
	cbor_mark_negint(key_1);
	int abs_key_1 = abs(E_U_map_param_1 - 1);
	cbor_set_uint8(key_1, abs_key_1);
	cbor_map_add(E_U,
			(struct cbor_pair )
					{ .key = cbor_move(key_1), .value = cbor_move(
							cbor_build_uint8(X25519_OKP_value)) });
	cbor_item_t *key_2;
	key_2 = cbor_new_int8();
	cbor_mark_negint(key_2);
	int abs_key_2 = abs(E_U_map_param_2 - 1);
	cbor_set_uint8(key_2, abs_key_2);
	cbor_map_add(E_U,
			(struct cbor_pair )
					{ .key = cbor_move(key_2), .value = cbor_move(
							cbor_build_bytestring(bstr_e_u, *bstr_e_u_sz)) });
	cbor_map_add(E_U, (struct cbor_pair )
			{ .key = cbor_move(cbor_build_uint8(E_U_map_param_3)), .value =
					cbor_move(cbor_build_uint8(COSE_key_object_type)) });
	if (!cbor_array_push(MSG, E_U)) {
		printf("\ncbor_array_push E_U FAILED.\n");
	}

	cbor_item_t *ECDH_Curves_U = cbor_new_definite_array(ECDH_Curves_ARRAY);
	for (int i = X25519; i <= X25519; i++) {
		cbor_item_t *alg = cbor_new_int8();
		alg = cbor_build_uint8(i);
		if (!cbor_array_push(ECDH_Curves_U, alg)) {
			printf("\ncbor_array_push alg in ECDH_Curves array FAILED.\n");
		}
	}
	if (!cbor_array_push(MSG, ECDH_Curves_U)) {
		printf("\ncbor_array_push ECDH_Curves_U FAILED.\n");
	}

	/*
	 * Push only ONE supported HKDF algorithm for now...
	 * */
	cbor_item_t *HKDFs_U = cbor_new_definite_array(HKDFs_ARRAY);
	/*
	 * Push ALL supported HKDF algorithms (work in progress)
	 */
	/*
	 for (HKDF_algorithms i = ECDH_ES_HKDF_256; i >= ECDH_SS_HKDF_512; i--)
	 {
	 cbor_item_t *alg = cbor_new_int8();
	 int abs_i = abs(i);
	 alg = cbor_build_uint8(abs_i - 1);
	 cbor_mark_negint(alg);
	 if (!cbor_array_push(HKDFs, alg))
	 {
	 printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
	 }
	 }
	 */
	cbor_item_t *hkdf_alg = cbor_new_int8();
	cbor_mark_negint(hkdf_alg);
	int abs_i = abs(ECDH_SS_HKDF_256) - 1;
	cbor_set_uint8(hkdf_alg, abs_i);
	if (!cbor_array_push(HKDFs_U, hkdf_alg)) {
		printf("\ncbor_array_push alg in HKDFs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, HKDFs_U)) {
		printf("\ncbor_array_push HKDFs_U FAILED.\n");
	}

	/*
	 * Push only ONE supported AEAD algorithm for now...
	 * */
	cbor_item_t *AEADs_U = cbor_new_definite_array(AEADs_ARRAY);
	/*
	 * Push ALL supported AEAD algorithms (work in progress)
	 * BUG AFTER i = AES_CCM_64_64_128
	 */
	/*
	 for (AEAD_algorithms i = AES_CCM_16_64_128; i <= AES_CCM_64_128_256; i++)
	 {
	 cbor_item_t *alg = cbor_new_int8(i);
	 alg = cbor_build_uint8(i);
	 if (!cbor_array_push(AEADs, alg))
	 {
	 printf("\ncbor_array_push alg in AEADs array FAILED.\n");
	 }
	 //if (i == 14)
	 //{
	 //  i = 30;
	 //}
	 }
	 */
	cbor_item_t *aead_alg = cbor_new_int8();
	aead_alg = cbor_build_uint8(AES_CCM_64_64_128);
	if (!cbor_array_push(AEADs_U, aead_alg)) {
		printf("\ncbor_array_push alg in AEADs array FAILED.\n");
	}
	if (!cbor_array_push(MSG, AEADs_U)) {
		printf("\ncbor_array_push AEADs_U FAILED.\n");
	}

	cbor_item_t *KID = cbor_new_definite_bytestring();
	unsigned char kid[] = PRE_SHARED_KEY_ID;
	KID = cbor_build_bytestring(kid, sizeof(kid));
	if (!cbor_array_push(MSG, KID)) {
		printf("\ncbor_array_push KID FAILED.\n");
	}

	if (app_1 != NULL) {
		cbor_item_t *APP_1 = cbor_new_definite_bytestring();
		APP_1 = cbor_build_bytestring(app_1, app_1_sz);
		if (!cbor_array_push(MSG, APP_1)) {
			printf("\ncbor_array_push APP_1 FAILED.\n");
		}
	}

	unsigned char *buffer;
	size_t buffer_sz, length = cbor_serialize_alloc(MSG, &buffer, &buffer_sz);

	message_1 = buffer;
	message_1_len = length;

	write_cbor_array_to_file_HEX(buffer, length, msg_type, filepath);

	write_cbor_array_to_file_RAW(buffer, length, msg_type, filepath);

	printf("\nmessage_%d msg_type: %d", get_msg_num(msg_type), msg_type);
	print_cbor_array_to_stdout(buffer, length);

	return buffer;
}
