/*
 * EdhocMessage1.c
 *
 *  Created on: Jun 29, 2018
 *      Author: vikram
 */
#include "edhoc.h"

struct msg_1_data MSG_1;
struct eu E_U;

/*
 * defines the structure of EDHOC Message 1.
 *
 * MSG_TYPE: 		indicates the message type.
 * S_U: 			variable length session identifier.
 * N_U: 			represents nonce.
 * E_U: 			ephemeral public key of the party U.
 * EDCH_Curves_U: 	EC curves for ECDH which Party U supports, in the
 * 					order of decreasing preference. (currently only one curve is supported)
 * HKDFs_U: 		supported ECDH-SS w/ HKDF algorithms. (currently only default
 * 					values are supported)
 * AEADs_U: 		supported AEAD algorithms (only defaults supported)
 * KID: 			identifier of the pre-shared key.
 * APP_1: 			bstr containing opaque application data.
 *
 */
struct msg_1_data {
	uint8_t MSG_TYPE;
	unsigned char *S_U;
	unsigned char * N_U;
	E_U *E_U;
	uint8_t ECDH_Curves_U;
	int8_t HKDFs_U;
	uint8_t AEADs_U;
	unsigned char *KID;
	unsigned char *APP_1;
};

/*
 *defines the serialized representation of cose key.
 *
 *param_1: indicates type of the curve used.
 *param_2: 'EC2' or 'OKP' curve either x, y coordinates or both.
 *param_3:	representing key type. ('EC2', 'OKP', 'Symmetric')
 */
struct eu {
	uint8_t param_1;
	unsigned char *param_2;
	uint8_t param_3;
};

/* unsecured message sent by the device in message1*/
unsigned char app_1[] = "Hello, my name is EDHOC!";

/**
 *This method constructs the EDHOC Message 1.
 *
 *@see: https://tools.ietf.org/html/draft-selander-ace-cose-ecdhe-08#section-5.2
 */
unsigned char *gen_msg1_sym(unsigned char *app_1, size_t app_1_sz,
		EVP_PKEY *pkey, const char *filepath)
{
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
	//size_t variable_length = rand() % (S_ID_MAX_SIZE + 1 - S_ID_MIN_SIZE) + S_ID_MIN_SIZE;
	//unsigned char *bstr_s_u = gen_random_S_ID(variable_length);
	//S_U = cbor_build_bytestring(bstr_s_u, variable_length);
	unsigned char s_id_party_U[] = S_ID_PARTY_U;
	unsigned char *bstr_s_u = (unsigned char *) S_ID_PARTY_U;
	S_U = cbor_build_bytestring(bstr_s_u, sizeof(S_ID_PARTY_U));
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

void *parse_edhoc_sym_msg1(cbor_item_t *MSG) {
	printf("\n#### PARSING EDHOC MESSAGE 1 ####\n");

	cbor_item_t *msg_type;
	msg_type = cbor_array_get(MSG, 0);
	uint8_t MSG_TYPE = cbor_get_uint8(msg_type);
	MSG_1->MSG_TYPE = MSG_TYPE;

	cbor_item_t *s_u;
	s_u = cbor_array_get(MSG, 1);
	size_t S_U_length = cbor_bytestring_length(s_u);
	unsigned char *S_U = cbor_bytestring_handle(s_u);
	MSG_1.S_U = S_U;

	cbor_item_t *n_u;
	n_u = cbor_array_get(MSG, 2);
	size_t N_U_length = cbor_bytestring_length(n_u);
	unsigned char *N_U = cbor_bytestring_handle(n_u);
	MSG_1.N_U = N_U;

	cbor_item_t *e_u;
	e_u = cbor_array_get(MSG, 3);
	struct cbor_pair *e_u_map_pairs = cbor_map_handle(e_u);
	cbor_item_t *crv = cbor_move(e_u_map_pairs[0].value);
	cbor_item_t *ephemeral_key = cbor_move(e_u_map_pairs[1].value);
	size_t ephemeral_key_sz = cbor_map_allocated(e_u_map_pairs[1].value);
	cbor_item_t *kty = cbor_move(e_u_map_pairs[2].value);
	E_U.param_1 = cbor_get_uint8(crv);
	E_U.param_2 = cbor_bytestring_handle(ephemeral_key);
	E_U.param_3 = cbor_get_uint8(kty);
	MSG_1.E_U = E_U;

	/*
	 * Retrieve the other Party's PUBKEY
	 */
	const char *filepath = "./edhoc_server_INBOX/client_PUBKEY.txt";
	unsigned char *key_pem_format = key_add_headers(E_U.param_2,
			ephemeral_key_sz, filepath);

	cbor_item_t *ecdh_curves_u;
	ecdh_curves_u = cbor_array_get(MSG, 4);
	uint8_t ECDH_Curves_U = cbor_get_uint8(cbor_array_get(ecdh_curves_u, 0));
	MSG_1.ECDH_Curves_U = ECDH_Curves_U;

	cbor_item_t *hkdfs_u;
	hkdfs_u = cbor_array_get(MSG, 5);
	int8_t HKDFs_U = cbor_get_uint8(cbor_array_get(hkdfs_u, 0));
	HKDFs_U = -HKDFs_U - 1;
	MSG_1.HKDFs_U = HKDFs_U;

	cbor_item_t *aeads_u;
	aeads_u = cbor_array_get(MSG, 6);
	uint8_t AEADs_U = cbor_get_uint8(cbor_array_get(aeads_u, 0));
	MSG_1.AEADs_U = AEADs_U;

	cbor_item_t *kid;
	kid = cbor_array_get(MSG, 7);
	size_t KID_length = cbor_bytestring_length(kid);
	unsigned char *KID = cbor_bytestring_handle(kid);
	MSG_1.KID = KID;

	cbor_item_t *app_1;
	unsigned char *APP_1 = NULL;
	size_t APP_1_length;
	if (cbor_array_size(MSG) == 9) {
		app_1 = cbor_array_get(MSG, 8);
		APP_1_length = cbor_bytestring_length(app_1);
		APP_1 = cbor_bytestring_handle(app_1);
		MSG_1.APP_1 = APP_1;
	}

	printf("\n-----BEGIN EDHOC MESSAGE DESCRIPTION-----\n");
	printf("   MSG_TYPE : %d", MSG_TYPE);
	printf("\n   S_U : ");
	print_cbor_bytestring_to_stdout(S_U, S_U_length);
	printf("\n   N_U : ");
	print_cbor_bytestring_to_stdout(N_U, N_U_length);
	printf("\n   E_U : ");
	printf("Param_1= %d ", E_U.param_1);
	printf("Param_2= ");
	print_cbor_bytestring_to_stdout_hex(E_U.param_2, ephemeral_key_sz);
	printf(" Param_3= %d", E_U.param_3);
	printf("\n   ECDH-Curves_U : %d", ECDH_Curves_U);
	printf("\n   HKDFs_U : %d", HKDFs_U);
	printf("\n   AEADs_U : %d", AEADs_U);
	printf("\n   KID : ");
	print_cbor_bytestring_to_stdout(KID, KID_length);
	if (APP_1 != NULL) {
		printf("\n   APP_1 : ");
		print_cbor_bytestring_to_stdout(APP_1, APP_1_length);
	} else {
		printf("\n   APP_1 : NULL (No data transmited)");
	}
	printf("\n-----END EDHOC MESSAGE DESCRIPTION-----\n");

	printf("\n#### END OF PARSING EDHOC MESSAGE 1 ####\n");

	return 0;
}
