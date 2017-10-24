#include <sys/ioctl.h>
#include <sys/types.h>

#include <ctype.h>

#include "version.h"
#include "pcap.h"
#include "adu-restful-serv.h"
#include "mongoose.h"
#include "airodump-ng.h"
#include "aircrack-ng-util.h"

extern struct globals G;

static void send_error_result(struct mg_connection *nc, const char *msg) {
	/* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nTransfer-Encoding: chunked\r\n\r\n");
  	mg_printf_http_chunk(nc, "Error: %s", msg);
  	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}


static void handle_hopper_switch(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	if (G.pid_hopper > 0)
		kill(G.pid_hopper, SIGUSR1);
	
	mg_printf_http_chunk(nc, "%s", "OK");
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
}


static void handle_get_stats(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	char *ap_list = dump_stats();
	mg_printf_http_chunk(nc, "%s", ap_list);
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
	free(ap_list);
}

static void handle_get_ap_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	char *ap_list = dump_ap_list();
	mg_printf_http_chunk(nc, "%s", ap_list);
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
	free(ap_list);
}

static void handle_get_sta_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	char *sta_list = dump_sta_list();
	mg_printf_http_chunk(nc, "%s", sta_list);
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
	free(sta_list);
}

static void handle_get_all_sta_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	char *sta_list = dump_all_sta_list();
	mg_printf_http_chunk(nc, "%s", sta_list);
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
	free(sta_list);
}

static void handle_get_na_list(struct mg_connection *nc, struct http_message *hm) {
	 /* Send headers */
  	mg_printf(nc, "%s", "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n");
	
	char *na_list = dump_na_list();
	mg_printf_http_chunk(nc, "%s", na_list);
	mg_send_http_chunk(nc, "", 0); /* Send empty chunk, the end of response */
	free(na_list);
}

static void adu_handler(struct mg_connection *nc, int ev, void *ev_data) {
	struct http_message *hm = (struct http_message *) ev_data;

	switch (ev) {
	case MG_EV_HTTP_REQUEST:
	  	if (mg_vcmp(&hm->uri, "/kunteng/getaplist") == 0) {
			handle_get_ap_list(nc, hm); /* Handle RESTful call */
	  	} else if (mg_vcmp(&hm->uri, "/kunteng/getstalist") == 0) {
			handle_get_sta_list(nc, hm);
		} else if (mg_vcmp(&hm->uri, "/kunteng/getallstalist") == 0) {
			handle_get_all_sta_list(nc, hm);
		} else if (mg_vcmp(&hm->uri, "/kunteng/getnalist") == 0) {
			handle_get_na_list(nc, hm);
		} else if (mg_vcmp(&hm->uri, "/kunteng/getstats") == 0) {
			handle_get_stats(nc, hm);
		} else if (mg_vcmp(&hm->uri, "/kunteng/hopperswitch") == 0) {
			handle_hopper_switch(nc, hm);
	  	} else {
			send_error_result(nc, "not support");
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
	
	char s_http_port[16] = {0};
	snprintf(s_http_port, sizeof(s_http_port), "%d", G.rest_port);
	nc = mg_bind_opt(&mgr, s_http_port, adu_handler, bind_opts);
	if (nc == NULL) {
		fprintf(stderr, "Error starting server on port %d: %s\n", G.rest_port,
			*bind_opts.error_string);
		exit(1);
	}

	mg_set_protocol_http_websocket(nc);

	for (;;) {
		mg_mgr_poll(&mgr, 1000);
	}
	mg_mgr_free(&mgr);

	return 0;
}
