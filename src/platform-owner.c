/**
 * Some LICENSE
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <coap3/coap.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

/* getaddrinfo() expects those to be strings */
#define COAP_SERVER_ADDR "169.254.0.1"
#define COAP_SERVER_PORT "5683"

#define MAX_URI_LEN 100

#define UNUSED  __attribute__((unused))

typedef struct {
	char		*chain_filename;
	char		*po_priv_filename;
	X509_NAME	*issuer_name;
	UsefulBuf	csr;
} app_data_t;

#ifndef X509_VERSION_3
#define X509_VERSION_3 2
#endif

static int get_cert_chain(UsefulBufC **certs, app_data_t *app_data)
{
	int num_objects = 0;
	int chain_size = 0;
	X509_STORE *store = NULL;
	X509_LOOKUP *lookup_ctx = NULL;
	STACK_OF(X509_OBJECT) *chain = NULL;
	X509_NAME *xn_cur = NULL, *xn_prev = NULL;

	/* TODO: add error checking for openssl calls */
	store = X509_STORE_new();
	lookup_ctx = X509_STORE_add_lookup(store, X509_LOOKUP_file());

	if (!X509_LOOKUP_load_file(lookup_ctx, app_data->chain_filename, X509_FILETYPE_PEM)) {
		fprintf(stderr, "Can't load certificates from '%s' - is file corrupted?\n",
			app_data->chain_filename);
		goto error;
	}

	chain = X509_STORE_get0_objects(store);
	num_objects = sk_X509_OBJECT_num(chain);

	*certs = calloc(num_objects, sizeof(UsefulBufC));

	for (int i = 0; i < num_objects; i++) {
		int len;
		int ca = 0;
		unsigned char *buf = NULL;
		X509 *cert = NULL;

		/* Check if object is a certificate */
		cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(chain, i));
		if (cert == NULL) {
			/* Either CRL or invalid object */
			fprintf(stderr, "Object with index %d is not a certificate!\n", i);
			continue;
		}

		ca = X509_check_ca(cert);
		if (ca == 0) {
			/* Can't be used for signing other certificates */
			fprintf(stderr, "Object with index %d is not a CA certificate!\n", i);
			continue;
		}

		if (ca != 1) {
			/* Can be used for signing, but doesn't have proper format */
			fprintf(stderr, "Object with index %d is not a X509v3 CA certificate!\n", i);
		}

		/* Convert to DER */
		len = i2d_X509(cert, &buf);
		if (len < 0) {
			fprintf(stderr, "Error during conversion to DER\n");
			goto error;
		}

		xn_prev = xn_cur;
		xn_cur = X509_get_subject_name(cert);

		/* Save pointers to DER certificates in returned array */
		(*certs)[chain_size].len = len;
		(*certs)[chain_size].ptr = buf;
		chain_size++;
	}

	app_data->issuer_name = X509_NAME_dup(xn_prev);

error:
	/* Tear down X509 resources */
	X509_LOOKUP_shutdown(lookup_ctx);
	X509_LOOKUP_free(lookup_ctx);

	return chain_size;
}

static void free_cert_chain(size_t size, UsefulBufC *p)
{
	for (size_t i = 0; i < size; i++) {
		OPENSSL_free((void*)p[i].ptr);
	}
	free(p);
}

static UsefulBuf _cbor_cert_chain(UsefulBuf buf, size_t num, UsefulBufC *certs)
{
	QCBOREncodeContext ctx;
	UsefulBufC enc;
	QCBORError err;
	QCBOREncode_Init(&ctx, buf);

	QCBOREncode_OpenMap(&ctx);
		QCBOREncode_OpenArrayInMap(&ctx, "certs");
		for (size_t i = 0; i < num; i++)
			QCBOREncode_AddBytes(&ctx, certs[i]);
		QCBOREncode_CloseArray(&ctx);
	QCBOREncode_CloseMap(&ctx);

	err = QCBOREncode_Finish(&ctx, &enc);

	if(err != QCBOR_SUCCESS) {
		fprintf(stderr, "QCBOR error: %d\n", err);
		return NULLUsefulBuf;
	} else {
		return UsefulBuf_Unconst(enc);
	}
}

static UsefulBuf cbor_cert_chain(app_data_t *app_data)
{
	UsefulBufC *certs = NULL;
	UsefulBuf ret = SizeCalculateUsefulBuf;
	int num_certs;

	num_certs = get_cert_chain(&certs, app_data);

	ret = _cbor_cert_chain(ret, num_certs, certs);
	ret.ptr = malloc(ret.len);
	ret = _cbor_cert_chain(ret, num_certs, certs);

	free_cert_chain(num_certs, certs);

	return ret;
}

static void add_serial(X509 *x509)
{
	/* FIXME: this should not be random, CA must keep track of certificates
	 * it issues
	 */
	BIGNUM *bn = NULL;
	unsigned char rnd[20];
	RAND_bytes(rnd, 20);
	bn = BN_bin2bn(rnd, 20, NULL);
	X509_set_serialNumber(x509, BN_to_ASN1_INTEGER(bn, NULL));
	BN_free(bn);
}

static void add_basic_constraints(X509 *x509)
{
	BASIC_CONSTRAINTS bc = { .ca = 0};
	ASN1_OCTET_STRING *ext_oct = NULL;
	X509_EXTENSION *ext = NULL;

	ext_oct = ASN1_OCTET_STRING_new();
	ext_oct->length = i2d_BASIC_CONSTRAINTS(&bc, &ext_oct->data);

	ext = X509_EXTENSION_create_by_NID(NULL, NID_basic_constraints, 1,
					   ext_oct);
	X509_add_ext(x509, ext, X509_get_ext_count(x509));

	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(ext_oct);
}

static void add_key_usage(X509 *x509)
{
	ASN1_BIT_STRING *bs = NULL;
	ASN1_OCTET_STRING *ext_oct = NULL;
	X509_EXTENSION *ext = NULL;

	bs = ASN1_BIT_STRING_new();
	/* Bit 0 is digitalSignature */
	ASN1_BIT_STRING_set_bit(bs, 0, 1);

	ext_oct = ASN1_OCTET_STRING_new();
	ext_oct->length = i2d_ASN1_BIT_STRING(bs, &ext_oct->data);

	ext = X509_EXTENSION_create_by_NID(NULL, NID_key_usage, 1, ext_oct);
	X509_add_ext(x509, ext, X509_get_ext_count(x509));

	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(ext_oct);
	ASN1_BIT_STRING_free(bs);
}

static ASN1_OCTET_STRING *get_keyid(X509_PUBKEY *pubkey)
{
	const unsigned char *pk = NULL;
	int pklen;
	unsigned diglen;
	unsigned char pkey_dig[EVP_MAX_MD_SIZE];
	ASN1_OCTET_STRING *oct = NULL;

	X509_PUBKEY_get0_param(NULL, &pk, &pklen, NULL, pubkey);

	EVP_Digest(pk, pklen, pkey_dig, &diglen, EVP_sha1(), NULL);

	oct = ASN1_OCTET_STRING_new();
	ASN1_OCTET_STRING_set(oct, pkey_dig, diglen);

	return oct;
}

static void add_skid(X509 *x509)
{
	ASN1_OCTET_STRING *oct = NULL, *ext_oct = NULL;
	X509_EXTENSION *ext = NULL;
	X509_PUBKEY *pubkey = NULL;

	/* 'pubkey' will point to somewhere inside 'x509', must not be freed */
	pubkey = X509_get_X509_PUBKEY(x509);
	oct = get_keyid(pubkey);

	ext_oct = ASN1_OCTET_STRING_new();
	ext_oct->length = i2d_ASN1_OCTET_STRING(oct, &ext_oct->data);

	ext = X509_EXTENSION_create_by_NID(NULL, NID_subject_key_identifier, 0,
					   ext_oct);
	X509_add_ext(x509, ext, X509_get_ext_count(x509));

	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(ext_oct);
	ASN1_OCTET_STRING_free(oct);
}

static void add_akid(X509 *x509, EVP_PKEY *ak_priv)
{
	ASN1_OCTET_STRING *ext_oct = NULL;
	X509_EXTENSION *ext = NULL;
	X509_PUBKEY *pubkey = NULL;
	AUTHORITY_KEYID akid = {0};

	/* New 'pubkey' is created, must be freed */
	X509_PUBKEY_set(&pubkey, ak_priv);
	akid.keyid = get_keyid(pubkey);

	ext_oct = ASN1_OCTET_STRING_new();
	ext_oct->length = i2d_AUTHORITY_KEYID(&akid, &ext_oct->data);

	ext = X509_EXTENSION_create_by_NID(NULL, NID_authority_key_identifier,
					   0, ext_oct);
	X509_add_ext(x509, ext, X509_get_ext_count(x509));

	X509_EXTENSION_free(ext);
	ASN1_OCTET_STRING_free(ext_oct);
	ASN1_OCTET_STRING_free(akid.keyid);
	X509_PUBKEY_free(pubkey);
}

static UsefulBuf create_cert(app_data_t *app_data, long days)
{
	EVP_PKEY *pkey;
	X509_REQ *req;
	ASN1_TIME *tm;
	UsefulBuf ub = NULLUsefulBuf;
	X509 *ret = NULL;
	int nid = NID_undef;
	const EVP_MD *md = EVP_md_null();
	/* Pointer to buffer is modified by d2i_* functions, make a copy */
	unsigned char *tmp_ptr = app_data->csr.ptr;
	/* UsefulBuf.len is unsigned and i2d_* return negative value on error */
	int len = 0;

	FILE *po_priv = fopen(app_data->po_priv_filename, "r");
	if (po_priv == NULL) {
		perror("Can't open private CA key file");
		return NULLUsefulBuf;
	}

	pkey = PEM_read_PrivateKey(po_priv, NULL, NULL, NULL);

	req = d2i_X509_REQ(NULL, (const unsigned char **)&tmp_ptr, app_data->csr.len);
	if (!req) {
		fprintf(stderr, "Invalid CSR\n");
		goto exit;
	}

	ret = X509_new();
	X509_set_version(ret, X509_VERSION_3);
	X509_NAME *xn = X509_REQ_get_subject_name(req);
	if (!xn) {
		fprintf(stderr, "X509_REQ_get_subject_name failed\n");
		goto exit;
	}

	X509_set_subject_name(ret, xn);
	X509_set_issuer_name(ret, app_data->issuer_name);
	tm = ASN1_TIME_adj(NULL, time(NULL), 0, 0);
	X509_set1_notBefore(ret, tm);
	tm = ASN1_TIME_adj(tm, time(NULL), days, 0);
	X509_set1_notAfter(ret, tm);
	ASN1_STRING_free(tm);

	EVP_PKEY *pubkey = X509_REQ_get0_pubkey(req);
	if (!pubkey) {
		fprintf(stderr, "X509_REQ_get0_pubkey failed\n");
		goto exit;
	}
	X509_set_pubkey(ret, pubkey);

	add_serial(ret);

	add_basic_constraints(ret);
	add_key_usage(ret);
	add_skid(ret);
	add_akid(ret, pkey);

	/* EVP_get_digestbynid(NID_undef) returns NULL, not EVP_md_null()... */
	if (EVP_PKEY_get_default_digest_nid(pkey, &nid) > 0 && nid != NID_undef)
		md = EVP_get_digestbynid(nid);

	/* TODO: blindly issuing certificates might be dangerous, add tests */
	X509_sign(ret, pkey, md);

	/* Following line won't even get called when error happens earlier */
	ERR_print_errors_fp(stdout);

	/* TODO: for testing only, remove when no longer needed */
	PEM_write_X509(stdout, ret);

	tmp_ptr = NULL;
	len = i2d_X509(ret, &tmp_ptr);
	if (len < 0) {
		fprintf(stderr, "i2d_X509() returned error: %d\n", len);
	} else {
		ub.ptr = tmp_ptr;
		ub.len = len;
	}

exit:
	if (req)
		X509_REQ_free(req);
	if (ret)
		X509_free(ret);
	fclose(po_priv);

	return ub;
}

static int resolve_address(coap_address_t *dst)
{
    struct addrinfo *res, *ainfo;
    struct addrinfo hints;
    int status;

    memset(&hints, 0, sizeof(hints));
    memset(dst, 0, sizeof(*dst));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;

    status = getaddrinfo(COAP_SERVER_ADDR, COAP_SERVER_PORT, &hints, &res);

    if (status != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return status;
    }

    for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
        if (ainfo->ai_family == AF_INET || ainfo->ai_family == AF_INET6) {
            dst->size = ainfo->ai_addrlen;
            memcpy(&dst->addr.sin6, ainfo->ai_addr, dst->size);
            break;
        }
    }

    freeaddrinfo(res);

    /* Return error if AF_INET* not found */
    return ainfo == NULL;
}

static void split_and_add_uri(coap_pdu_t *pdu, const char *path)
{
	size_t len = MAX_URI_LEN;
	unsigned char _buf[MAX_URI_LEN] = {0};
	unsigned char *buf = _buf;
	int res;
	coap_optlist_t *optlist = NULL;

	res = coap_split_path((const unsigned char*)path, strlen(path), buf, &len);
	while (res--) {
		coap_insert_optlist(&optlist,
			coap_new_optlist(COAP_OPTION_URI_PATH,
				     coap_opt_length(buf),
				     coap_opt_value(buf)));

		buf += coap_opt_size(buf);
	}
	coap_add_optlist_pdu(pdu, &optlist);
	coap_delete_optlist(optlist);
}

static coap_pdu_code_t response;

/* NOTE: this function does not free memory allocated by payload */
static int common_cbor_post(coap_context_t *ctx, coap_session_t *session,
                            const char *path, UsefulBuf payload, int mediatype,
                            coap_response_handler_t handler)
{
	coap_pdu_t *pdu = NULL;
	int ret_response;
	unsigned char buf[3];

	/* Construct CoAP message */
	pdu = coap_pdu_init(COAP_MESSAGE_CON,
			COAP_REQUEST_CODE_POST,
			coap_new_message_id(session),
			coap_session_max_pdu_size(session));
	if (!pdu) {
		coap_log(LOG_EMERG, "%s: cannot create PDU\n", path);
		return -1;
	}

	/* Add a Uri-Path option */
	split_and_add_uri(pdu, path);

	/* Add Content-Format option */
	coap_add_option(pdu, COAP_OPTION_CONTENT_FORMAT,
	                coap_encode_var_safe(buf, sizeof(buf), mediatype), buf);

	/* Add data - must be after all options are added */
	if (!coap_add_data_large_request(session, pdu, payload.len, payload.ptr,
				     NULL, NULL)) {
		coap_log(LOG_EMERG, "Couldn't add data to PDU\n");
		free(payload.ptr);
		coap_delete_pdu(pdu);
		return -1;
	}

	coap_show_pdu(LOG_INFO, pdu);

	coap_register_response_handler(ctx, handler);

	/* Send the PDU (releases memory allocated for PDU) */
	coap_send(session, pdu);

	/* Wait for response */
	while (response == 0)
		coap_io_process(ctx, COAP_IO_WAIT);

	/* Clear flag and unregister handler for further requests */
	ret_response = response;
	response = 0;
	coap_register_response_handler(ctx, NULL);

	return ret_response;
}

static coap_response_t provision_response_handler(coap_session_t UNUSED *session,
                                               const coap_pdu_t UNUSED *sent,
                                               const coap_pdu_t *received,
                                               const coap_mid_t UNUSED mid)
{
	app_data_t *app_data = coap_session_get_app_data(session);
	response = coap_pdu_get_code(received);
	UsefulBufC ub = NULLUsefulBufC;

	coap_show_pdu(LOG_INFO, received);

	if (response != COAP_RESPONSE_CODE_CREATED)
		return COAP_RESPONSE_OK;

	if (!coap_get_data(received, &ub.len, (const uint8_t **)&ub.ptr)) {
		coap_log(LOG_EMERG, "CSR doesn't contain any data\n");
		return COAP_RESPONSE_OK;
	}

	app_data->csr.ptr = malloc(ub.len);
	app_data->csr.len = ub.len;
	memcpy(app_data->csr.ptr, ub.ptr, ub.len);

	return COAP_RESPONSE_OK;
}

static int provision_request(coap_context_t *ctx, coap_session_t *session)
{
	app_data_t *app_data = coap_session_get_app_data(session);
	const char path[] = "api/v1/admin/token_provision";
	int ret = -1;

	UsefulBuf ub = cbor_cert_chain(app_data);
	if (UsefulBuf_IsNULLOrEmpty(ub)) {
		return ret;
	}

	ret = common_cbor_post(ctx, session, path, ub,
	                       COAP_MEDIATYPE_APPLICATION_CBOR,
	                       provision_response_handler);

	free(ub.ptr);
	return ret;
}

static coap_response_t finish_response_handler(coap_session_t UNUSED *session,
                                               const coap_pdu_t UNUSED *sent,
                                               const coap_pdu_t *received,
                                               const coap_mid_t UNUSED mid)
{
	response = coap_pdu_get_code(received);

	coap_show_pdu(LOG_INFO, received);

	return COAP_RESPONSE_OK;
}

static int finish_request(coap_context_t *ctx, coap_session_t *session)
{
	const char path[] = "api/v1/admin/provision_complete";
	app_data_t *app_data = coap_session_get_app_data(session);
	int ret = -1;

	UsefulBuf ub = create_cert(app_data, 365);
	if (UsefulBuf_IsNULLOrEmpty(ub)) {
		return -1;
	}

	ret = common_cbor_post(ctx, session, path, ub,
	                       COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
	                       finish_response_handler);

	free(app_data->csr.ptr);
	app_data->csr = NULLUsefulBuf;
	OPENSSL_clear_free(ub.ptr, ub.len);
	return ret;
}

/* --------------------------- main ----------------------------- */

int main(int argc, char *argv[])
{
	coap_context_t  *ctx = NULL;
	coap_session_t *session = NULL;
	coap_address_t dst;
	int result = EXIT_SUCCESS;
	app_data_t app_data = {0};

	/* TODO: parse CLI arguments with getopt if needed */
	if (argc < 3) {
		printf("Usage: %s path/to/cert_chain.pem path/to/po_priv_key.pem\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE *f = fopen(argv[1], "r");
	if (f == NULL) {
		perror("fopen() failed");
		printf("Usage: %s path/to/cert_chain.pem path/to/po_priv_key.pem\n", argv[0]);
		return EXIT_FAILURE;
	} else {
		fclose(f);
		app_data.chain_filename = argv[1];
	}

	f = fopen(argv[2], "r");
	if (f == NULL) {
		perror("fopen() failed");
		printf("Usage: %s path/to/cert_chain.pem path/to/po_priv_key.pem\n", argv[0]);
		return EXIT_FAILURE;
	} else {
		fclose(f);
		app_data.po_priv_filename = argv[2];
	}

	coap_startup();

	/* Set logging level */
	coap_set_log_level(LOG_DEBUG);

	/* Resolve destination address where server should be sent */
	if (resolve_address(&dst)) {
		coap_log(LOG_CRIT, "Failed to resolve address\n");
		goto finish;
	}

	/* Create CoAP context and a client session */
	if (!(ctx = coap_new_context(NULL))) {
		coap_log(LOG_EMERG, "Cannot create libcoap context\n");
		goto finish;
	}
	/* Support large responses */
	coap_context_set_block_mode(ctx,
		  COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

	if (!(session = coap_new_client_session(ctx, NULL, &dst,
						  COAP_PROTO_UDP))) {
	coap_log(LOG_EMERG, "Cannot create client session\n");
		goto finish;
	}

	coap_session_set_app_data(session, &app_data);

	result = provision_request(ctx, session);
	if (result != COAP_RESPONSE_CODE_CREATED) {
		coap_log(LOG_EMERG, "Unexpected response for provision request (%s)\n",
		         (result > 0 && coap_response_phrase((uint8_t)result)) ?
		         coap_response_phrase((uint8_t)result) : "not a CoAP error");
		goto finish;
	}

	result = finish_request(ctx, session);
	if (result != COAP_RESPONSE_CODE_CREATED) {
		coap_log(LOG_EMERG, "Unexpected response for provision complete request (%s)\n",
		         (result > 0 && coap_response_phrase((uint8_t)result)) ?
		         coap_response_phrase((uint8_t)result) : "not a CoAP error");
		goto finish;
	}

finish:
	if (app_data.issuer_name)
		X509_NAME_free(app_data.issuer_name);

	coap_session_release(session);
	coap_free_context(ctx);
	coap_cleanup();

	return result;
}
