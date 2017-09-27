#include "pcap.h"
#include "adu-restful-serv.h"
#include "mongoose.h"
#include "airodump-ng.h"

static void handle_get_ap_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

static void handle_get_sta_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}

static void adu_handler(struct mg_connection *nc, int ev, void *ev_data) {
	struct http_message *hm = (struct http_message *) ev_data;

	switch (ev) {
	case MG_EV_HTTP_REQUEST:
	  	if (mg_vcmp(&hm->uri, "/kunteng/getaplist") == 0) {
			handle_get_ap_list(nc, hm); /* Handle RESTful call */
	  	} else if (mg_vcmp(&hm->uri, "/kunteng/getstalist") == 0) {
			handle_get_sta_list(nc, hm);
	  	} else {
		}
	  	break;
	default:
	  	break;
	}
}

void adu_restful_serv_thread( void *arg)
{
	struct mg_mgr mgr;
  	struct mg_connection *nc = NULL;
  	struct mg_bind_opts bind_opts;
  	int i;
  	char *cp = NULL;
  	const char *err_str;
#if MG_ENABLE_SSL
  	const char *ssl_cert = NULL;
#endif

  	mg_mgr_init(&mgr, NULL);

	/* Set HTTP server options */
	memset(&bind_opts, 0, sizeof(bind_opts));
	bind_opts.error_string = &err_str;
#if MG_ENABLE_SSL
	if (ssl_cert != NULL) {
		bind_opts.ssl_cert = ssl_cert;
	}
#endif

	nc = mg_bind_opt(&mgr, G.rest_port, adu_handler, bind_opts);
	if (nc == NULL) {
		fprintf(stderr, "Error starting server on port %s: %s\n", G.rest_port,
			*bind_opts.error_string);
		exit(1);
	}

	mg_set_protocol_http_websocket(nc);
	s_http_server_opts.enable_directory_listing = "no";

	for (;;) {
		mg_mgr_poll(&mgr, 1000);
	}
	mg_mgr_free(&mgr);

	return 0;
}
