#ifndef _AIRCRACK_NG_UTIL_H_
#define _AIRCRACK_NG_UTIL_H_

//#define RATE_ESTIMATOR

int is_filtered_netmask(unsigned char *bssid);

int is_filtered_essid(unsigned char *essid);

void resetSelection();

void input_thread( void *arg);

int check_shared_key(unsigned char *h80211, int caplen);

struct oui;
FILE *open_oui_file(void);
struct oui * load_oui_file(void);

struct pkt_buf;

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet);

int list_tail_free(struct pkt_buf **list);

int remove_namac(unsigned char* mac);

char * getStringTimeFromSec(double seconds);

int get_sta_list_count();

int get_ap_list_count();

char * get_manufacturer_from_string(char * buffer);

void dump_sort( void );

void dump_print( int ws_row, int ws_col, int if_num );

void reset_term();

void textstyle(int attr);

void textcolor_bg(int bg);

void textcolor_fg(int fg);

void textcolor(int attr, int fg, int bg);

unsigned long calc_rate_est(struct AP_info *ap);

void rate_estimator(struct AP_info *ap);

char *dump_ap_list(); //caizhibang add 

char *dump_sta_list(); 

char *dump_all_sta_list(); 

char *dump_na_list();

#endif
