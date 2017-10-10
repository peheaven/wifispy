#ifndef _AIRCRACK_NG_UTIL_H_
#define _AIRCRACK_NG_UTIL_H_

int is_filtered_netmask(unsigned char *bssid);

int is_filtered_essid(unsigned char *essid);

void resetSelection();

void input_thread( void *arg);

int check_shared_key(unsigned char *h80211, int caplen);

struct oui;
struct oui * load_oui_file(void);

struct pkt_buf;

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet);

int list_tail_free(struct pkt_buf **list);

int remove_namac(unsigned char* mac);

char * getStringTimeFromSec(double seconds);

int get_sta_list_count();

int get_ap_list_count();

#endif
