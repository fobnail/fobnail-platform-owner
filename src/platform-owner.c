/**
 * Some LICENSE
 */

#include <stdio.h>
#include <arpa/inet.h>
#include <coap3/coap.h>
#include <signal.h>
#include <qcbor/UsefulBuf.h>

static volatile sig_atomic_t quit = 0;
static const char LISTEN_ADDRESS[] = "0.0.0.0";
static unsigned int port = COAP_DEFAULT_PORT; /* default port 5683 */

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

static void coap_cert_chain_handler(struct coap_resource_t* resource,
				    struct coap_session_t* session,
				    const struct coap_pdu_t* in,
				    const struct coap_string_t* query,
				    struct coap_pdu_t* out)
{
	int ret;

	printf("Received message: %s\n", coap_get_uri_path(in)->s);

	UsefulBuf ub = NULLUsefulBuf;

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

#define UNUSED  __attribute__((unused))

int main(int UNUSED argc, char UNUSED *argv[])
{
	int result = EXIT_SUCCESS;

	/* signal handling */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* TODO: parse CLI arguments if needed */

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
