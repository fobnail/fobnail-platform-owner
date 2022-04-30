/**
 * Some LICENSE
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/safestack.h>

static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; /* default port 5683 */
static X509_NAME *issuer_name = NULL;

struct {
	char *chain_filename;
	char *po_priv_filename;
} args;

static void signal_handler(int signum)
{
	quit = signum;
}

static void coap_free_wrapper(coap_session_t *session, void *app_ptr)
{
	(void)session; /* unused */
	if (app_ptr != NULL)
		free(app_ptr);
}

static void coap_OPENSSL_free_wrapper(coap_session_t *session, void *app_ptr)
{
	(void)session; /* unused */
	UsefulBuf *ub = app_ptr;
	if (ub->ptr != NULL)
		OPENSSL_clear_free(ub->ptr, ub->len);
}

static int get_cert_chain(UsefulBufC **certs)
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

	if (!X509_LOOKUP_load_file(lookup_ctx, args.chain_filename, X509_FILETYPE_PEM)) {
		fprintf(stderr, "Can't load certificates from '%s' - is file corrupted?\n",
			args.chain_filename);
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

	issuer_name = X509_NAME_dup(xn_prev);

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

static UsefulBuf cbor_cert_chain(void)
{
	UsefulBufC *certs = NULL;
	UsefulBuf ret = SizeCalculateUsefulBuf;
	int num_certs;

	num_certs = get_cert_chain(&certs);

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
	/* TODO */
	(void)x509;
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

static UsefulBuf create_cert(UsefulBuf csr, long days)
{
	EVP_PKEY *pkey;
	X509_REQ *req;
	ASN1_TIME *tm;
	UsefulBuf ub = NULLUsefulBuf;
	/* Pointer to buffer is modified by d2i_* functions, make a copy */
	unsigned char *tmp_ptr = csr.ptr;
	/* UsefulBuf.len is unsigned and i2d_* return negative value on error */
	int len = 0;

	FILE *po_priv = fopen(args.po_priv_filename, "r");
	if (po_priv == NULL) {
		perror("Can't open private CA key file");
		return NULLUsefulBuf;
	}

	pkey = PEM_read_PrivateKey(po_priv, NULL, NULL, NULL);

	req = d2i_X509_REQ(NULL, (const unsigned char **)&tmp_ptr, csr.len);

	X509 *ret = X509_new();
	X509_set_version(ret, 2);
	X509_NAME *xn = X509_REQ_get_subject_name(req);
	X509_set_subject_name(ret, xn);
	X509_set_issuer_name(ret, issuer_name);
	tm = ASN1_TIME_adj(NULL, time(NULL), 0, 0);
	X509_set1_notBefore(ret, tm);
	tm = ASN1_TIME_adj(tm, time(NULL), days, 0);
	X509_set1_notAfter(ret, tm);
	ASN1_STRING_free(tm);

	X509_set_pubkey(ret, X509_REQ_get0_pubkey(req));

	add_serial(ret);

	add_basic_constraints(ret);
	add_key_usage(ret);
	add_skid(ret);
	add_akid(ret, pkey);

	/* TODO: blindly issuing certificates might be dangerous, add tests */
	X509_sign(ret, pkey, EVP_sha256());

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

	X509_REQ_free(req);
	X509_free(ret);
	fclose(po_priv);

	return ub;
}

static void coap_cert_chain_handler(struct coap_resource_t* resource,
				    struct coap_session_t* session,
				    const struct coap_pdu_t* in,
				    const struct coap_string_t* query,
				    struct coap_pdu_t* out)
{
	int ret;

	printf("Received message: %s\n", coap_get_uri_path(in)->s);

	UsefulBuf ub = cbor_cert_chain();

	/* prepare and send response */
	coap_pdu_set_code(out, COAP_RESPONSE_CODE_CONTENT);
	ret = coap_add_data_large_response(resource,
					   session,
					   in,
					   out,
					   query,
					   COAP_MEDIATYPE_APPLICATION_CBOR,
					   -1,
					   0,
					   ub.len,
					   ub.ptr,
					   coap_free_wrapper,
					   ub.ptr);
	if (ret == 0)
		fprintf(stderr, "Err: cannot response.\n");

}

static void coap_csr_handler(struct coap_resource_t* resource,
			     struct coap_session_t* session,
			     const struct coap_pdu_t* in,
			     const struct coap_string_t* query,
			     struct coap_pdu_t* out)
{
	int ret;
	size_t len, total, offset;
	static UsefulBuf ub;
	const uint8_t *data;

	printf("Received message: %s\n", coap_get_uri_path(in)->s);

	coap_get_data_large(in, &len, &data, &offset, &total);

	/* First PDU */
	if (UsefulBuf_IsNULLOrEmpty(ub)) {
		ub.ptr = malloc(total);
		ub.len = total;
	}

	memcpy((uint8_t *)ub.ptr + offset, data, len);

	/* Last PDU */
	if (total == offset + len) {
		/* Prepare and send response */
		/* Will be used by asynchronous callback, can't be on stack */
		static UsefulBuf ub2;
		ub2 = create_cert(ub, 365);

		coap_pdu_set_code(out, COAP_RESPONSE_CODE_CREATED);
		ret = coap_add_data_large_response(resource,
						   session,
						   in,
						   out,
						   query,
						   COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
						   -1,
						   0,
						   ub2.len,
						   ub2.ptr,
						   coap_OPENSSL_free_wrapper,
						   &ub2);
		free(ub.ptr);
		ub = NULLUsefulBuf;
		ub2 = NULLUsefulBuf;
		if (ret == 0)
			fprintf(stderr, "Err: cannot response.\n");
	}
}

void add_resource_wrapper(struct coap_context_t* coap_context,
			  coap_request_t method, const char* resource_name,
			  coap_method_handler_t handler)
{
	coap_str_const_t* resource_uri = coap_new_str_const((uint8_t const*)resource_name, strlen(resource_name));
	coap_resource_t* resource =
		coap_resource_init(resource_uri, COAP_RESOURCE_FLAGS_RELEASE_URI);
	coap_register_handler(resource, method, handler);
	coap_add_resource(coap_context, resource);
}

coap_endpoint_t* coap_new_endpoint_wrapper(coap_context_t* coap_context,
					   const char* listen_address,
					   const uint16_t port,
					   const coap_proto_t coap_protocol)
{
	/* prepare address */
	coap_address_t addr = {0};
	coap_address_init(&addr);
	addr.addr.sin.sin_family = AF_INET;
	inet_pton(AF_INET, listen_address, &addr.addr.sin.sin_addr);
	addr.addr.sin.sin_port = htons(port);

	/* create endpoint */
	return coap_new_endpoint(coap_context, &addr, coap_protocol);
}

/* --------------------------- main ----------------------------- */

int main(int argc, char *argv[])
{
	int result = EXIT_SUCCESS;

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
		args.chain_filename = argv[1];
	}

	f = fopen(argv[2], "r");
	if (f == NULL) {
		perror("fopen() failed");
		printf("Usage: %s path/to/cert_chain.pem path/to/po_priv_key.pem\n", argv[0]);
		return EXIT_FAILURE;
	} else {
		fclose(f);
		args.po_priv_filename = argv[2];
	}

	/* signal handling */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	coap_context_t* coap_context = NULL;
	coap_endpoint_t* coap_endpoint = NULL;

	coap_context = coap_new_context(NULL);
	if (coap_context == NULL) {
		printf("Cannot create CoAP context.\n");
		result = EXIT_FAILURE;
		goto error;
	}
	/* enable block handling by libcoap */
	coap_context_set_block_mode(coap_context, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

	printf("Creating CoAP server endpoint using UDP.\n");
	if ((coap_endpoint = coap_new_endpoint_wrapper(coap_context, LISTEN_ADDRESS,
		port, COAP_PROTO_UDP)) == NULL) {
		printf("Cannot create CoAP server endpoint based on UDP.\n");
		result = EXIT_FAILURE;
		goto error;
	}

	/* register CoAP resource and resource handler */
	printf("Registering CoAP resources.\n");
	add_resource_wrapper(coap_context, COAP_REQUEST_FETCH, "cert_chain",
			     coap_cert_chain_handler);
	add_resource_wrapper(coap_context, COAP_REQUEST_POST, "csr",
			     coap_csr_handler);

	/* enter main loop */
	printf("Entering main loop.\n");
	while (!quit) {
		/* process CoAP I/O */
		if (coap_io_process(coap_context, COAP_IO_WAIT) == -1) {
			printf("Error during CoAP I/O processing.\n");
			result = EXIT_FAILURE;
			quit = 1;
		}
	}

error:
	if (issuer_name)
		X509_NAME_free(issuer_name);

	/* free CoAP memory */
	coap_free_endpoint(coap_endpoint);
	coap_endpoint = NULL;
	coap_free_context(coap_context);
	coap_context = NULL;

	coap_cleanup();

	return result;
}
