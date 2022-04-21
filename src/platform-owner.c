/**
 * Some LICENSE
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <qcbor/UsefulBuf.h>
#include <qcbor/qcbor_encode.h>
#include <openssl/x509.h>
#include <openssl/safestack.h>

static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; /* default port 5683 */
static char *chain_filename = NULL;

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

static int get_cert_chain(UsefulBufC **certs)
{
	int num_objects = 0;
	int chain_size = 0;
	X509_STORE *store = NULL;
	X509_LOOKUP *lookup_ctx = NULL;
	STACK_OF(X509_OBJECT) *chain = NULL;

	/* TODO: add error checking for openssl calls */
	store = X509_STORE_new();
	lookup_ctx = X509_STORE_add_lookup(store, X509_LOOKUP_file());

	if (!X509_LOOKUP_load_file(lookup_ctx, chain_filename, X509_FILETYPE_PEM)) {
		fprintf(stderr, "Can't load certificates from '%s' - is file corrupted?\n",
			chain_filename);
		goto error;
	}

	chain = X509_STORE_get0_objects(store);
	num_objects = sk_X509_OBJECT_num(chain);

	*certs = calloc(num_objects, sizeof(UsefulBufC));

	for (int i = 0; i < num_objects; i++) {
		int len;
		unsigned char *buf = NULL;
		X509 *cert = NULL;

		/* Check if object is a certificate */
		cert = X509_OBJECT_get0_X509(sk_X509_OBJECT_value(chain, i));
		if (cert == NULL) {
			/* Either CRL or invalid object */
			fprintf(stderr, "Object with index %d is not a certificate!\n", i);
			continue;
		}

		/* Convert to DER */
		len = i2d_X509(cert, &buf);
		if (len < 0) {
			fprintf(stderr, "Error during conversion to DER\n");
			goto error;
		}

		/* Save pointers to DER certificates in returned array */
		(*certs)[chain_size].len = len;
		(*certs)[chain_size].ptr = buf;
		chain_size++;
	}

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
		QCBOREncode_AddUInt64ToMap(&ctx, "num_certs", num);
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
					   COAP_MEDIATYPE_APPLICATION_OCTET_STREAM,
					   -1,
					   0,
					   ub.len,
					   ub.ptr,
					   coap_free_wrapper,
					   ub.ptr);
	if (ret == 0)
		fprintf(stderr, "Err: cannot response.\n");

}

void add_resource_wrapper(struct coap_context_t* coap_context,
			  coap_request_t method, const char* resource_name,
			  coap_method_handler_t handler)
{
	coap_resource_t* resource =
		coap_resource_init(coap_make_str_const(resource_name),
				   COAP_RESOURCE_FLAGS_RELEASE_URI);
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
	if (argc < 2) {
		printf("Usage: %s path/to/cert_chain.pem\n", argv[0]);
		return EXIT_FAILURE;
	}

	FILE *f = fopen(argv[1], "r");
	if (f == NULL) {
		perror("fopen() failed");
		printf("Usage: %s path/to/cert_chain.pem\n", argv[0]);
		return EXIT_FAILURE;
	} else {
		fclose(f);
		chain_filename = argv[1];
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
	/* free CoAP memory */
	coap_free_endpoint(coap_endpoint);
	coap_endpoint = NULL;
	coap_free_context(coap_context);
	coap_context = NULL;

	coap_cleanup();

	return result;
}
