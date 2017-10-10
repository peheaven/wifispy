#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#ifndef TIOCGWINSZ
	#include <sys/termios.h>
#endif

#include <time.h>
#include <termios.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>

#include <json-c/json.h> //caizhibang add

#include "crypto.h"
#include "common.h"
#include "pcap.h"
#include "aircrack-ng-util.h"
#include "airodump-ng.h"

extern struct globals G;

const char *OUI_PATHS[] = {
    "/etc/aircrack-ng/airodump-ng-oui.txt",
    "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt",
    "/usr/share/aircrack-ng/airodump-ng-oui.txt",
    "/var/lib/misc/oui.txt",
    "/usr/share/misc/oui.txt",
    "/var/lib/ieee-data/oui.txt",
    "/usr/share/ieee-data/oui.txt",
    "/etc/manuf/oui.txt",
    "/usr/share/wireshark/wireshark/manuf/oui.txt",
    "/usr/share/wireshark/manuf/oui.txt",
    NULL
};

int is_filtered_netmask(unsigned char *bssid)
{
    unsigned char mac1[6] = {0};
    unsigned char mac2[6] = {0};
    int i;

    for(i=0; i<6; i++)
    {
        mac1[i] = bssid[i]     & G.f_netmask[i];
        mac2[i] = G.f_bssid[i] & G.f_netmask[i];
    }

    if( memcmp(mac1, mac2, 6) != 0 )
    {
        return( 1 );
    }

    return 0;
}

int is_filtered_essid(unsigned char *essid)
{
    int ret = 0;
    int i;

    if(G.f_essid)
    {
        for(i=0; i<G.f_essid_count; i++)
        {
            if(strncmp((char*)essid, G.f_essid[i], MAX_IE_ELEMENT_SIZE) == 0)
            {
                return 0;
            }
        }

        ret = 1;
    }

#ifdef HAVE_PCRE
    if(G.f_essid_regex)
    {
        return pcre_exec(G.f_essid_regex, NULL, (char*)essid, strnlen((char *)essid, MAX_IE_ELEMENT_SIZE), 0, 0, NULL, 0) < 0;
    }
#endif

    return ret;
}

char * get_manufacturer_from_string(char * buffer) {
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0) {
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL) {
			buffer_manuf += 6; // skip '(hex)' and one more character (there's at least one 'space' character after that string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ') {
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0') {

				// First make sure there's no end of line
				if (buffer_manuf[strlen(buffer_manuf) - 1] == '\n' || buffer_manuf[strlen(buffer_manuf) - 1] == '\r') {
					buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					if (*buffer_manuf != '\0' && (buffer_manuf[strlen(buffer_manuf) - 1] == '\n' || buffer[strlen(buffer_manuf) - 1] == '\r')) {
						buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0') {
					if ((manuf = (char *)malloc((strlen(buffer_manuf) + 1) * sizeof(char))) == NULL) {
						perror("malloc failed");
						return NULL;
					}
					snprintf(manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return manuf;
}

void textcolor(int attr, int fg, int bg)
{	char command[13];

	/* Command is the control command to the terminal */
	snprintf(command, sizeof(command), "%c[%d;%d;%dm", 0x1B, attr, fg + 30, bg + 40);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textcolor_fg(int fg)
{	char command[13];

	/* Command is the control command to the terminal */
	snprintf(command, sizeof(command), "\033[%dm", fg + 30);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textcolor_bg(int bg)
{	char command[13];

	/* Command is the control command to the terminal */
	snprintf(command, sizeof(command), "\033[%dm", bg + 40);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void textstyle(int attr)
{	char command[13];

	/* Command is the control command to the terminal */
	snprintf(command, sizeof(command), "\033[%im", attr);
	fprintf(stderr, "%s", command);
	fflush(stderr);
}

void reset_term() {
  struct termios oldt,
                 newt;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag |= ( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
}

int mygetch( ) {
  struct termios oldt,
                 newt;
  int            ch;
  tcgetattr( STDIN_FILENO, &oldt );
  newt = oldt;
  newt.c_lflag &= ~( ICANON | ECHO );
  tcsetattr( STDIN_FILENO, TCSANOW, &newt );
  ch = getchar();
  tcsetattr( STDIN_FILENO, TCSANOW, &oldt );
  return ch;
}

void resetSelection()
{
    G.sort_by = SORT_BY_POWER;
    G.sort_inv = 1;

    G.start_print_ap=1;
    G.start_print_sta=1;
    G.selected_ap=1;
    G.selected_sta=1;
    G.selection_ap=0;
    G.selection_sta=0;
    G.mark_cur_ap=0;
    G.skip_columns=0;
    G.do_pause=0;
    G.do_sort_always=0;
    memset(G.selected_bssid, '\x00', 6);
}

int list_tail_free(struct pkt_buf **list)
{
    struct pkt_buf **pkts = NULL;
    struct pkt_buf *next = NULL;

    if(list == NULL) return 1;

    pkts = list;

    while(*pkts != NULL)
    {
        next = (*pkts)->next;
        if( (*pkts)->packet )
        {
            free( (*pkts)->packet);
            (*pkts)->packet=NULL;
        }

        if(*pkts)
        {
            free(*pkts);
            *pkts = NULL;
        }
        *pkts = next;
    }

    *list=NULL;

    return 0;
}

int list_add_packet(struct pkt_buf **list, int length, unsigned char* packet)
{
    struct pkt_buf *next = *list;

    if(length <= 0) return 1;
    if(packet == NULL) return 1;
    if(list == NULL) return 1;

    *list = (struct pkt_buf*) malloc(sizeof(struct pkt_buf));
    if( *list == NULL ) return 1;
    (*list)->packet = (unsigned char*) malloc(length);
    if( (*list)->packet == NULL ) return 1;

    memcpy((*list)->packet,  packet, length);
    (*list)->next = next;
    (*list)->length = length;
    gettimeofday( &((*list)->ctime), NULL);

    return 0;
}

int remove_namac(unsigned char* mac)
{
    struct NA_info *na_cur = NULL;
    struct NA_info *na_prv = NULL;

    if(mac == NULL)
        return( -1 );

    na_cur = G.na_1st;
    na_prv = NULL;

    while( na_cur != NULL )
    {
        if( ! memcmp( na_cur->namac, mac, 6 ) )
            break;

        na_prv = na_cur;
        na_cur = na_cur->next;
    }

    /* if it's known, remove it */
    if( na_cur != NULL )
    {
        /* first in linked list */
        if(na_cur == G.na_1st)
        {
            G.na_1st = na_cur->next;
        }
        else
        {
            na_prv->next = na_cur->next;
        }
        free(na_cur);
        na_cur=NULL;
    }

    return( 0 );
}

#define KEY_TAB		0x09	//switch between APs/clients for scrolling
#define KEY_SPACE	0x20	//pause/resume output
#define KEY_ARROW_UP	0x41	//scroll
#define KEY_ARROW_DOWN	0x42	//scroll
#define KEY_ARROW_RIGHT 0x43	//scroll
#define KEY_ARROW_LEFT	0x44	//scroll
#define KEY_a		0x61	//cycle through active information (ap/sta/ap+sta/ap+sta+ack)
#define KEY_c		0x63	//cycle through channels
#define KEY_d		0x64	//default mode
#define KEY_i		0x69	//inverse sorting
#define KEY_m		0x6D	//mark current AP
#define KEY_n		0x6E	//?
#define KEY_r		0x72	//realtime sort (de)activate
#define KEY_s		0x73	//cycle through sorting

void input_thread( void *arg) {

    if(!arg){}

    while( G.do_exit == 0 ) {
	int keycode=0;

	keycode=mygetch();

	if(keycode == KEY_s) {
	    G.sort_by++;
	    G.selection_ap = 0;
	    G.selection_sta = 0;

	    if(G.sort_by > MAX_SORT)
		G.sort_by = 0;

	    switch(G.sort_by) {
		case SORT_BY_NOTHING:
		    snprintf(G.message, sizeof(G.message), "][ sorting by first seen");
		    break;
		case SORT_BY_BSSID:
		    snprintf(G.message, sizeof(G.message), "][ sorting by bssid");
		    break;
		case SORT_BY_POWER:
		    snprintf(G.message, sizeof(G.message), "][ sorting by power level");
		    break;
		case SORT_BY_BEACON:
		    snprintf(G.message, sizeof(G.message), "][ sorting by beacon number");
		    break;
		case SORT_BY_DATA:
		    snprintf(G.message, sizeof(G.message), "][ sorting by number of data packets");
		    break;
		case SORT_BY_PRATE:
		    snprintf(G.message, sizeof(G.message), "][ sorting by packet rate");
		    break;
		case SORT_BY_CHAN:
		    snprintf(G.message, sizeof(G.message), "][ sorting by channel");
		    break;
		case SORT_BY_MBIT:
		    snprintf(G.message, sizeof(G.message), "][ sorting by max data rate");
		    break;
		case SORT_BY_ENC:
		    snprintf(G.message, sizeof(G.message), "][ sorting by encryption");
		    break;
		case SORT_BY_CIPHER:
		    snprintf(G.message, sizeof(G.message), "][ sorting by cipher");
		    break;
		case SORT_BY_AUTH:
		    snprintf(G.message, sizeof(G.message), "][ sorting by authentication");
		    break;
		case SORT_BY_ESSID:
		    snprintf(G.message, sizeof(G.message), "][ sorting by ESSID");
		    break;
		default:
		    break;
	    }
	    pthread_mutex_lock( &(G.mx_sort) );
		dump_sort();
	    pthread_mutex_unlock( &(G.mx_sort) );
	}

	if(keycode == KEY_SPACE) {
	    G.do_pause = (G.do_pause+1)%2;
	    if(G.do_pause) {
		snprintf(G.message, sizeof(G.message), "][ paused output");
		pthread_mutex_lock( &(G.mx_print) );

		    fprintf( stderr, "\33[1;1H" );
		    dump_print( G.ws.ws_row, G.ws.ws_col, G.num_cards );
		    fprintf( stderr, "\33[J" );
		    fflush(stderr);

		pthread_mutex_unlock( &(G.mx_print) );
	    }
	    else
		snprintf(G.message, sizeof(G.message), "][ resumed output");
	}

	if(keycode == KEY_r) {
	    G.do_sort_always = (G.do_sort_always+1)%2;
	    if(G.do_sort_always)
			snprintf(G.message, sizeof(G.message), "][ realtime sorting activated");
	    else
			snprintf(G.message, sizeof(G.message), "][ realtime sorting deactivated");
	}

	if(keycode == KEY_m) {
	    G.mark_cur_ap = 1;
	}

	if(keycode == KEY_ARROW_DOWN) {
	    if(G.selection_ap == 1) {
		G.selected_ap++;
	    }
	    if(G.selection_sta == 1) {
		G.selected_sta++;
	    }
	}

	if(keycode == KEY_ARROW_UP) {
	    if(G.selection_ap == 1) {
		G.selected_ap--;
		if(G.selected_ap < 1)
		    G.selected_ap = 1;
	    }
	    if(G.selection_sta == 1) {
		G.selected_sta--;
		if(G.selected_sta < 1)
		    G.selected_sta = 1;
	    }
	}

	if(keycode == KEY_i) {
	    G.sort_inv*=-1;
	    if(G.sort_inv < 0)
		snprintf(G.message, sizeof(G.message), "][ inverted sorting order");
	    else
		snprintf(G.message, sizeof(G.message), "][ normal sorting order");
	}

	if(keycode == KEY_TAB) {
	    if(G.selection_ap == 0) {
		G.selection_ap = 1;
		G.selected_ap = 1;
		snprintf(G.message, sizeof(G.message), "][ enabled AP selection");
		G.sort_by = SORT_BY_NOTHING;
	    } else if(G.selection_ap == 1) {
		G.selection_ap = 0;
		G.sort_by = SORT_BY_NOTHING;
		snprintf(G.message, sizeof(G.message), "][ disabled selection");
	    }
	}

	if(keycode == KEY_a) {
	    if(G.show_ap == 1 && G.show_sta == 1 && G.show_ack == 0) {
			G.show_ap = 1;
			G.show_sta = 1;
			G.show_ack = 1;
			snprintf(G.message, sizeof(G.message), "][ display ap+sta+ack");
	    } else if(G.show_ap == 1 && G.show_sta == 1 && G.show_ack == 1) {
			G.show_ap = 1;
			G.show_sta = 0;
			G.show_ack = 0;
			snprintf(G.message, sizeof(G.message), "][ display ap only");
	    } else if(G.show_ap == 1 && G.show_sta == 0 && G.show_ack == 0) {
			G.show_ap = 0;
			G.show_sta = 1;
			G.show_ack = 0;
			snprintf(G.message, sizeof(G.message), "][ display sta only");
	    } else if(G.show_ap == 0 && G.show_sta == 1 && G.show_ack == 0) {
			G.show_ap = 1;
			G.show_sta = 1;
			G.show_ack = 0;
			snprintf(G.message, sizeof(G.message), "][ display ap+sta");
	    }
	}

	if (keycode == KEY_d) {
		resetSelection();
		snprintf(G.message, sizeof(G.message), "][ reset selection to default");
	}

	if(G.do_exit == 0 && !G.do_pause) {
	    pthread_mutex_lock( &(G.mx_print) );

		fprintf( stderr, "\33[1;1H" );
		dump_print( G.ws.ws_row, G.ws.ws_col, G.num_cards );
		fprintf( stderr, "\33[J" );
		fflush(stderr);

	    pthread_mutex_unlock( &(G.mx_print) );
	}
    } // end while
}

int check_shared_key(unsigned char *h80211, int caplen)
{
    int m_bmac, m_smac, m_dmac, n, textlen;
    char ofn[1024] = {0};
    char text[4096] = {0};
    char prga[4096] = {0};
    unsigned int long crc;

    if((unsigned)caplen > sizeof(G.sharedkey[0])) return 1;

    m_bmac = 16;
    m_smac = 10;
    m_dmac = 4;

    if( time(NULL) - G.sk_start > 5)
    {
        /* timeout(5sec) - remove all packets, restart timer */
        memset(G.sharedkey, '\x00', 4096*3);
        G.sk_start = time(NULL);
    }

    /* is auth packet */
    if( (h80211[1] & 0x40) != 0x40 )
    {
        /* not encrypted */
        if( ( h80211[24] + (h80211[25] << 8) ) == 1 )
        {
            /* Shared-Key Authentication */
            if( ( h80211[26] + (h80211[27] << 8) ) == 2 )
            {
                /* sequence == 2 */
                memcpy(G.sharedkey[0], h80211, caplen);
                G.sk_len = caplen-24;
            }
            if( ( h80211[26] + (h80211[27] << 8) ) == 4 )
            {
                /* sequence == 4 */
                memcpy(G.sharedkey[2], h80211, caplen);
            }
        }
        else return 1;
    }
    else
    {
        /* encrypted */
        memcpy(G.sharedkey[1], h80211, caplen);
        G.sk_len2 = caplen-24-4;
    }

    /* check if the 3 packets form a proper authentication */

    if( ( memcmp(G.sharedkey[0]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[1]+m_bmac, NULL_MAC, 6) == 0 ) ||
        ( memcmp(G.sharedkey[2]+m_bmac, NULL_MAC, 6) == 0 ) ) /* some bssids == zero */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[1]+m_bmac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_bmac, G.sharedkey[2]+m_bmac, 6) != 0 ) ) /* all bssids aren't equal */
    {
        return 1;
    }

    if( ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[2]+m_smac, 6) != 0 ) ||
        ( memcmp(G.sharedkey[0]+m_smac, G.sharedkey[1]+m_dmac, 6) != 0 ) ) /* SA in 2&4 != DA in 3 */
    {
        return 1;
    }

    if( (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[2]+m_dmac, 6) != 0 ) ||
        (memcmp(G.sharedkey[0]+m_dmac, G.sharedkey[1]+m_smac, 6) != 0 ) ) /* DA in 2&4 != SA in 3 */
    {
        return 1;
    }

    textlen = G.sk_len;

    if(textlen+4 != G.sk_len2)
    {
        snprintf(G.message, sizeof(G.message), "][ Broken SKA: %02X:%02X:%02X:%02X:%02X:%02X ",
                    *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
                *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));
        return 1;
    }

    if((unsigned)textlen > sizeof(text) - 4) return 1;

    memcpy(text, G.sharedkey[0]+24, textlen);

    /* increment sequence number from 2 to 3 */
    text[2] = text[2]+1;

    crc = 0xFFFFFFFF;

    for( n = 0; n < textlen; n++ )
        crc = crc_tbl[(crc ^ text[n]) & 0xFF] ^ (crc >> 8);

    crc = ~crc;

    /* append crc32 over body */
    text[textlen]     = (crc      ) & 0xFF;
    text[textlen+1]   = (crc >>  8) & 0xFF;
    text[textlen+2]   = (crc >> 16) & 0xFF;
    text[textlen+3]   = (crc >> 24) & 0xFF;

    /* cleartext XOR cipher */
    for(n=0; n<(textlen+4); n++)
    {
        prga[4+n] = (text[n] ^ G.sharedkey[1][28+n]) & 0xFF;
    }

    /* write IV+index */
    prga[0] = G.sharedkey[1][24] & 0xFF;
    prga[1] = G.sharedkey[1][25] & 0xFF;
    prga[2] = G.sharedkey[1][26] & 0xFF;
    prga[3] = G.sharedkey[1][27] & 0xFF;

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf( ofn, sizeof( ofn ) - 1, "%s-%02d-%02X-%02X-%02X-%02X-%02X-%02X.%s", G.prefix, G.f_index,
              *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5), "xor" );

    G.f_xor = fopen( ofn, "w");
    if(G.f_xor == NULL)
        return 1;

    for(n=0; n<textlen+8; n++)
        fputc((prga[n] & 0xFF), G.f_xor);

    fflush(G.f_xor);

    if( G.f_xor != NULL )
    {
        fclose(G.f_xor);
        G.f_xor = NULL;
    }

    snprintf(G.message, sizeof(G.message), "][ %d bytes keystream: %02X:%02X:%02X:%02X:%02X:%02X ",
                textlen+4, *(G.sharedkey[0]+m_bmac), *(G.sharedkey[0]+m_bmac+1), *(G.sharedkey[0]+m_bmac+2),
              *(G.sharedkey[0]+m_bmac+3), *(G.sharedkey[0]+m_bmac+4), *(G.sharedkey[0]+m_bmac+5));

    memset(G.sharedkey, '\x00', 512*3);
    /* ok, keystream saved */
    return 0;
}

FILE *open_oui_file(void) {
	int i;
	FILE *fp = NULL;

	for (i=0; OUI_PATHS[i] != NULL; i++) {
		fp = fopen(OUI_PATHS[i], "r");
		if ( fp != NULL ) {
			break;
		}
	}

	return fp;
}

struct oui * load_oui_file(void) {
	FILE *fp;
	char * manuf;
	char buffer[BUFSIZ];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	struct oui *oui_ptr = NULL, *oui_head = NULL;

	fp = open_oui_file();
	if (!fp) {
		return NULL;
	}

	memset(buffer, 0x00, sizeof(buffer));
	while (fgets(buffer, sizeof(buffer), fp) != NULL) {
		if (!(strstr(buffer, "(hex)")))
			continue;

		memset(a, 0x00, sizeof(a));
		memset(b, 0x00, sizeof(b));
		memset(c, 0x00, sizeof(c));
		// Remove leading/trailing whitespaces.
		trim(buffer);
		if (sscanf(buffer, "%2c-%2c-%2c", a, b, c) == 3) {
			if (oui_ptr == NULL) {
				if (!(oui_ptr = (struct oui *)malloc(sizeof(struct oui)))) {
					fclose(fp);
					perror("malloc failed");
					return NULL;
				}
			} else {
				if (!(oui_ptr->next = (struct oui *)malloc(sizeof(struct oui)))) {
					fclose(fp);
					perror("malloc failed");

					while(oui_head != NULL)
					{
						oui_ptr = oui_head->next;
						free(oui_head);
						oui_head = oui_ptr;
					}
					return NULL;
				}
				oui_ptr = oui_ptr->next;
			}
			memset(oui_ptr->id, 0x00, sizeof(oui_ptr->id));
			memset(oui_ptr->manuf, 0x00, sizeof(oui_ptr->manuf));
			snprintf(oui_ptr->id, sizeof(oui_ptr->id), "%c%c:%c%c:%c%c", a[0], a[1], b[0], b[1], c[0], c[1]);
			manuf = get_manufacturer_from_string(buffer);
			if (manuf != NULL) {
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "%s", manuf);
				free(manuf);
			} else {
				snprintf(oui_ptr->manuf, sizeof(oui_ptr->manuf), "Unknown");
			}
			if (oui_head == NULL)
				oui_head = oui_ptr;
			oui_ptr->next = NULL;
		}
	}

	fclose(fp);
	return oui_head;
}

char * getStringTimeFromSec(double seconds)
{
    int hour[3];
    char * ret;
    char * HourTime;
    char * MinTime;

    if (seconds <0)
        return NULL;

    ret = (char *) calloc(1,256);

    HourTime = (char *) calloc (1,128);
    MinTime  = (char *) calloc (1,128);

    hour[0]  = (int) (seconds);
    hour[1]  = hour[0] / 60;
    hour[2]  = hour[1] / 60;
    hour[0] %= 60 ;
    hour[1] %= 60 ;

    if (hour[2] != 0 )
        snprintf(HourTime, 128, "%d %s", hour[2], ( hour[2] == 1 ) ? "hour" : "hours");
    if (hour[1] != 0 )
        snprintf(MinTime, 128, "%d %s", hour[1], ( hour[1] == 1 ) ? "min" : "mins");

    if ( hour[2] != 0 && hour[1] != 0 )
        snprintf(ret, 256, "%s %s", HourTime, MinTime);
    else
    {
        if (hour[2] == 0 && hour[1] == 0)
            snprintf(ret, 256, "%d s", hour[0] );
        else
            snprintf(ret, 256, "%s", (hour[2] == 0) ? MinTime : HourTime );
    }

    free(MinTime);
    free(HourTime);

    return ret;
}

static void dump_ap_sort()
{
	time_t tt = time(NULL);
	struct AP_info *new_ap_1st = NULL;
	struct AP_info *new_ap_end = NULL;
	struct AP_info *ap_cur, *ap_min;
	
	while(G.ap_1st) {
		ap_min = NULL;
		ap_cur = G.ap_1st;
		
		while( ap_cur != NULL )
        {
            if( tt - ap_cur->tlast > 20 )
                ap_min = ap_cur;

            ap_cur = ap_cur->next;
        }

        if( ap_min == NULL )
        {
            ap_min = ap_cur = G.ap_1st;

/*#define SORT_BY_BSSID 1
#define SORT_BY_POWER   2
#define SORT_BY_BEACON  3
#define SORT_BY_DATA    4
#define SORT_BY_PRATE   6
#define SORT_BY_CHAN    7
#define SORT_BY_MBIT    8
#define SORT_BY_ENC     9
#define SORT_BY_CIPHER  10
#define SORT_BY_AUTH    11
#define SORT_BY_ESSID   12*/
			while( ap_cur != NULL )
            {
                switch (G.sort_by) {
                    case SORT_BY_BSSID:
                        if( memcmp(ap_cur->bssid,ap_min->bssid,6)*G.sort_inv < 0)
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_POWER:
                        if( (ap_cur->avg_power - ap_min->avg_power)*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_BEACON:
                        if( (ap_cur->nb_bcn < ap_min->nb_bcn)*G.sort_inv )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_DATA:
                        if( (ap_cur->nb_data < ap_min->nb_data)*G.sort_inv )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_PRATE:
                        if( (ap_cur->nb_dataps - ap_min->nb_dataps)*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_CHAN:
                        if( (ap_cur->channel - ap_min->channel)*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_MBIT:
                        if( (ap_cur->max_speed - ap_min->max_speed)*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_ENC:
                        if( ((ap_cur->security&STD_FIELD) - (ap_min->security&STD_FIELD))*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_CIPHER:
                        if( ((ap_cur->security&ENC_FIELD) - (ap_min->security&ENC_FIELD))*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_AUTH:
                        if( ((ap_cur->security&AUTH_FIELD) - (ap_min->security&AUTH_FIELD))*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    case SORT_BY_ESSID:
                        if( (strncasecmp((char*)ap_cur->essid, (char*)ap_min->essid, MAX_IE_ELEMENT_SIZE))*G.sort_inv < 0 )
                            ap_min = ap_cur;
                        break;
                    default:    //sort by power
                        if( ap_cur->avg_power < ap_min->avg_power)
							ap_min = ap_cur;
                        break;
                }
                ap_cur = ap_cur->next;
            }
        }

        if( ap_min == G.ap_1st )
            G.ap_1st = ap_min->next;

        if( ap_min == G.ap_end )
            G.ap_end = ap_min->prev;

        if( ap_min->next )
            ap_min->next->prev = ap_min->prev;

        if( ap_min->prev )
            ap_min->prev->next = ap_min->next;

        if( new_ap_end )
        {
            new_ap_end->next = ap_min;
            ap_min->prev = new_ap_end;
            new_ap_end = ap_min;
            new_ap_end->next = NULL;
        }
        else
        {
            new_ap_1st = new_ap_end = ap_min;
            ap_min->next = ap_min->prev = NULL;
        }
    }

    G.ap_1st = new_ap_1st;
    G.ap_end = new_ap_end;
}


static void dump_sta_sort()
{
	struct ST_info *new_st_1st = NULL;
    struct ST_info *new_st_end = NULL;
	struct ST_info *st_cur, *st_min;
	
	time_t tt = time( NULL );
	
	while( G.st_1st )
    {
        st_min = NULL;
        st_cur = G.st_1st;

        while( st_cur != NULL )
        {
            if( tt - st_cur->tlast > 60 )
                st_min = st_cur;
            
            st_cur = st_cur->next;
        }

        if( st_min == NULL )
        {
            st_min = st_cur = G.st_1st;

            while( st_cur != NULL )
            {
                if( st_cur->power < st_min->power)
                    st_min = st_cur;
                
                st_cur = st_cur->next;
            }
        }

        if( st_min == G.st_1st )
            G.st_1st = st_min->next;

        if( st_min == G.st_end )
            G.st_end = st_min->prev;

        if( st_min->next )
            st_min->next->prev = st_min->prev;

        if( st_min->prev )
            st_min->prev->next = st_min->next;

        if( new_st_end )
        {
            new_st_end->next = st_min;
            st_min->prev = new_st_end;
            new_st_end = st_min;
            new_st_end->next = NULL;
        } else {
            new_st_1st = new_st_end = st_min;
            st_min->next = st_min->prev = NULL;
        }
    }

    G.st_1st = new_st_1st;
    G.st_end = new_st_end;		
}

void dump_sort( void )
{
    time_t tt = time( NULL );

    /* thanks to Arnaud Cornet :-) */

    struct AP_info *new_ap_1st = NULL;
    struct AP_info *new_ap_end = NULL;

    struct ST_info *new_st_1st = NULL;
    struct ST_info *new_st_end = NULL;

    struct ST_info *st_cur, *st_min;
    struct AP_info *ap_cur, *ap_min;

    /* sort the aps by WHATEVER first */

    while( G.ap_1st )
    {
        ap_min = NULL;
        ap_cur = G.ap_1st;

        while( ap_cur != NULL )
        {
            if( tt - ap_cur->tlast > 20 )
                ap_min = ap_cur;

            ap_cur = ap_cur->next;
        }

        if( ap_min == NULL )
        {
            ap_min = ap_cur = G.ap_1st;

/*#define SORT_BY_BSSID	1
#define SORT_BY_POWER	2
#define SORT_BY_BEACON	3
#define SORT_BY_DATA	4
#define SORT_BY_PRATE	6
#define SORT_BY_CHAN	7
#define	SORT_BY_MBIT	8
#define SORT_BY_ENC	9
#define SORT_BY_CIPHER	10
#define SORT_BY_AUTH	11
#define SORT_BY_ESSID	12*/

	    while( ap_cur != NULL )
            {
		switch (G.sort_by) {
		    case SORT_BY_BSSID:
			if( memcmp(ap_cur->bssid,ap_min->bssid,6)*G.sort_inv < 0)
			    ap_min = ap_cur;
			break;
		    case SORT_BY_POWER:
			if( (ap_cur->avg_power - ap_min->avg_power)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_BEACON:
			if( (ap_cur->nb_bcn < ap_min->nb_bcn)*G.sort_inv )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_DATA:
			if( (ap_cur->nb_data < ap_min->nb_data)*G.sort_inv )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_PRATE:
			if( (ap_cur->nb_dataps - ap_min->nb_dataps)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_CHAN:
			if( (ap_cur->channel - ap_min->channel)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_MBIT:
			if( (ap_cur->max_speed - ap_min->max_speed)*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_ENC:
			if( ((ap_cur->security&STD_FIELD) - (ap_min->security&STD_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_CIPHER:
			if( ((ap_cur->security&ENC_FIELD) - (ap_min->security&ENC_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_AUTH:
			if( ((ap_cur->security&AUTH_FIELD) - (ap_min->security&AUTH_FIELD))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    case SORT_BY_ESSID:
			if( (strncasecmp((char*)ap_cur->essid, (char*)ap_min->essid, MAX_IE_ELEMENT_SIZE))*G.sort_inv < 0 )
			    ap_min = ap_cur;
			break;
		    default:	//sort by power
			if( ap_cur->avg_power < ap_min->avg_power)
			    ap_min = ap_cur;
			break;
		}
                ap_cur = ap_cur->next;
	    }
	}

        if( ap_min == G.ap_1st )
            G.ap_1st = ap_min->next;

        if( ap_min == G.ap_end )
            G.ap_end = ap_min->prev;

        if( ap_min->next )
            ap_min->next->prev = ap_min->prev;

        if( ap_min->prev )
            ap_min->prev->next = ap_min->next;

        if( new_ap_end )
        {
            new_ap_end->next = ap_min;
            ap_min->prev = new_ap_end;
            new_ap_end = ap_min;
            new_ap_end->next = NULL;
        }
        else
        {
            new_ap_1st = new_ap_end = ap_min;
            ap_min->next = ap_min->prev = NULL;
        }
    }

    G.ap_1st = new_ap_1st;
    G.ap_end = new_ap_end;

    /* now sort the stations */

    while( G.st_1st )
    {
        st_min = NULL;
        st_cur = G.st_1st;

        while( st_cur != NULL )
        {
            if( tt - st_cur->tlast > 60 )
                st_min = st_cur;

            st_cur = st_cur->next;
        }

        if( st_min == NULL )
        {
            st_min = st_cur = G.st_1st;

            while( st_cur != NULL )
            {
                if( st_cur->power < st_min->power)
                    st_min = st_cur;

                st_cur = st_cur->next;
            }
        }

        if( st_min == G.st_1st )
            G.st_1st = st_min->next;

        if( st_min == G.st_end )
            G.st_end = st_min->prev;

        if( st_min->next )
            st_min->next->prev = st_min->prev;

        if( st_min->prev )
            st_min->prev->next = st_min->next;

        if( new_st_end )
        {
            new_st_end->next = st_min;
            st_min->prev = new_st_end;
            new_st_end = st_min;
            new_st_end->next = NULL;
        }
        else
        {
            new_st_1st = new_st_end = st_min;
            st_min->next = st_min->prev = NULL;
        }
    }

    G.st_1st = new_st_1st;
    G.st_end = new_st_end;
}

#define TSTP_SEC 1000000ULL /* It's a 1 MHz clock, so a million ticks per second! */
#define TSTP_MIN (TSTP_SEC * 60ULL)
#define TSTP_HOUR (TSTP_MIN * 60ULL)
#define TSTP_DAY (TSTP_HOUR * 24ULL)

static char *parse_timestamp(unsigned long long timestamp) {
	static char s[15];
	unsigned long long rem;
	unsigned int days, hours, mins, secs;

	days = timestamp / TSTP_DAY;
	rem = timestamp % TSTP_DAY;
	hours = rem / TSTP_HOUR;
	rem %= TSTP_HOUR;
	mins = rem / TSTP_MIN;
	rem %= TSTP_MIN;
	secs = rem / TSTP_SEC;

	snprintf(s, 14, "%3ud %02u:%02u:%02u", days, hours, mins, secs);

	return s;
}

void dump_print( int ws_row, int ws_col, int if_num )
{
    time_t tt;
    struct tm *lt;
    int nlines, i, n, len;
    char strbuf[512];
    char buffer[512];
    char ssid_list[512];
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    struct NA_info *na_cur;
    int columns_ap = 83;
    int columns_sta = 74;
    int columns_na = 68;

    int num_ap;
    int num_sta;

    if(!G.singlechan) columns_ap -= 4; //no RXQ in scan mode
    if(G.show_uptime) columns_ap += 15; //show uptime needs more space

    nlines = 2;

    if( nlines >= ws_row )
        return;

    if(G.do_sort_always) {
		pthread_mutex_lock( &(G.mx_sort) );
	    dump_sort();
		pthread_mutex_unlock( &(G.mx_sort) );
    }

    tt = time( NULL );
    lt = localtime( &tt );

    if(G.is_berlin)
    {
        G.maxaps = 0;
        G.numaps = 0;
        ap_cur = G.ap_end;

        while( ap_cur != NULL )
        {
            G.maxaps++;
            if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
                memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
            {
                ap_cur = ap_cur->prev;
                continue;
            }
            G.numaps++;
            ap_cur = ap_cur->prev;
        }

        if(G.numaps > G.maxnumaps)
            G.maxnumaps = G.numaps;

//        G.maxaps--;
    }

    /*
     *  display the channel, battery, position (if we are connected to GPSd)
     *  and current time
     */

    memset( strbuf, '\0', sizeof(strbuf) );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    if(G.freqoption)
    {
        snprintf(strbuf, sizeof(strbuf)-1, " Freq %4d", G.frequency[0]);
        for(i=1; i<if_num; i++)
        {
            memset( buffer, '\0', sizeof(buffer) );
            snprintf(buffer, sizeof(buffer) , ",%4d", G.frequency[i]);
            strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) - 1);
        }
    }
    else
    {
        snprintf(strbuf, sizeof(strbuf)-1, " CH %2d", G.channel[0]);
        for(i=1; i<if_num; i++)
        {
            memset( buffer, '\0', sizeof(buffer) );
            snprintf(buffer, sizeof(buffer) , ",%2d", G.channel[i]);
            strncat(strbuf, buffer, sizeof(strbuf) - strlen(strbuf) -1);
        }
    }
    memset( buffer, '\0', sizeof(buffer) );

    if (G.gps_loc[0]) {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ GPS %8.3f %8.3f %8.3f %6.2f "
              "][ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ", G.batt,
              G.gps_loc[0], G.gps_loc[1], G.gps_loc[2], G.gps_loc[3],
              G.elapsed_time , 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }
    else
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              " %s[ Elapsed: %s ][ %04d-%02d-%02d %02d:%02d ",
              G.batt, G.elapsed_time, 1900 + lt->tm_year,
              1 + lt->tm_mon, lt->tm_mday, lt->tm_hour, lt->tm_min );
    }

    strncat(strbuf, buffer, (512-strlen(strbuf)));
    memset( buffer, '\0', 512 );

    if(G.is_berlin)
    {
        snprintf( buffer, sizeof( buffer ) - 1,
              " ][%3d/%3d/%4d ",
              G.numaps, G.maxnumaps, G.maxaps);
    }

    strncat(strbuf, buffer, (512-strlen(strbuf)));
    memset( buffer, '\0', 512 );

    if(strlen(G.message) > 0)
    {
        strncat(strbuf, G.message, (512-strlen(strbuf)));
    }

    //add traling spaces to overwrite previous messages
    strncat(strbuf, "                                        ", (512-strlen(strbuf)));

    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    /* print some informations about each detected AP */

    nlines += 3;

    if( nlines >= ws_row )
        return;

    memset( strbuf, ' ', ws_col - 1 );
    strbuf[ws_col - 1] = '\0';
    fprintf( stderr, "%s\n", strbuf );

    if(G.show_ap) {

    strbuf[0] = 0;
    strcat(strbuf, " BSSID              PWR ");

    if(G.singlechan)
    	strcat(strbuf, "RXQ ");

    strcat(strbuf, " Beacons    #Data, #/s  CH  MB   ENC  CIPHER AUTH ");

    if (G.show_uptime)
    	strcat(strbuf, "       UPTIME  ");

    if (G.show_wps)
    {
        strcat(strbuf, "WPS   ");
        if ( ws_col > (columns_ap - 4) )
        {
            memset(strbuf+columns_ap, 32, G.maxsize_wps_seen - 6 );
            snprintf(strbuf+columns_ap+G.maxsize_wps_seen-6, 9,"%s","   ESSID");
            if ( G.show_manufacturer  )
            {
                memset(strbuf+columns_ap+G.maxsize_wps_seen+2, 32, G.maxsize_essid_seen-5 );
                snprintf(strbuf+columns_ap+G.maxsize_essid_seen-5, 15,"%s","  MANUFACTURER");
            }
        }
    }
    else
    {
    strcat(strbuf, "ESSID");

	if ( G.show_manufacturer && ( ws_col > (columns_ap - 4) ) ) {
		// write spaces (32).
		memset(strbuf+columns_ap, 32, G.maxsize_essid_seen - 5 ); // 5 is the len of "ESSID"
		snprintf(strbuf+columns_ap+G.maxsize_essid_seen-5, 15,"%s","  MANUFACTURER");
	}
    }
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	memset( strbuf, ' ', ws_col - 1 );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	ap_cur = G.ap_end;

	if(G.selection_ap) {
	    num_ap = get_ap_list_count();
	    if(G.selected_ap > num_ap)
		G.selected_ap = num_ap;
	}

	if(G.selection_sta) {
	    num_sta = get_sta_list_count();
	    if(G.selected_sta > num_sta)
		G.selected_sta = num_sta;
	}

	num_ap = 0;

	if(G.selection_ap) {
	    G.start_print_ap = G.selected_ap - ((ws_row-1) - nlines) + 1;
	    if(G.start_print_ap < 1)
		G.start_print_ap = 1;
    //	printf("%i\n", G.start_print_ap);
	}


	while( ap_cur != NULL ) {
	    /* skip APs with only one packet, or those older than 2 min.
	    * always skip if bssid == broadcast */

	    if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
		memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 ) {
			ap_cur = ap_cur->prev;
			continue;
	    }

	    if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0)) {
			ap_cur = ap_cur->prev;
			continue;
	    }

	    if(is_filtered_essid(ap_cur->essid)) {
			ap_cur = ap_cur->prev;
			continue;
	    }

	    num_ap++;

	    if(num_ap < G.start_print_ap) {
			ap_cur = ap_cur->prev;
			continue;
	    }

	    nlines++;

	    if( nlines > (ws_row-1) )
		return;

	    memset(strbuf, '\0', sizeof(strbuf));

	    snprintf( strbuf, sizeof(strbuf), " %02X:%02X:%02X:%02X:%02X:%02X",
		    ap_cur->bssid[0], ap_cur->bssid[1],
		    ap_cur->bssid[2], ap_cur->bssid[3],
		    ap_cur->bssid[4], ap_cur->bssid[5] );

	    len = strlen(strbuf);

	    if(G.singlechan) {
			snprintf( strbuf+len, sizeof(strbuf)-len, "  %3d %3d %8lu %8lu %4d",
				ap_cur->avg_power,
				ap_cur->rx_quality,
				ap_cur->nb_bcn,
				ap_cur->nb_data,
				ap_cur->nb_dataps );
	    } else {
			snprintf( strbuf+len, sizeof(strbuf)-len, "  %3d %8lu %8lu %4d",
				ap_cur->avg_power,
				ap_cur->nb_bcn,
				ap_cur->nb_data,
				ap_cur->nb_dataps );
	    }

	    len = strlen(strbuf);

	    snprintf( strbuf+len, sizeof(strbuf)-len, " %3d %3d%c%c ",
		    ap_cur->channel, ap_cur->max_speed,
		    ( ap_cur->security & STD_QOS ) ? 'e' : ' ',
		    ( ap_cur->preamble ) ? '.' : ' ');

	    len = strlen(strbuf);

	    if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0) snprintf( strbuf+len, sizeof(strbuf)-len, "    " );
	    else if( ap_cur->security & STD_WPA2 ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA2" );
	    else if( ap_cur->security & STD_WPA  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WPA " );
	    else if( ap_cur->security & STD_WEP  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP " );
	    else if( ap_cur->security & STD_OPN  ) snprintf( strbuf+len, sizeof(strbuf)-len, "OPN " );

	    strncat( strbuf, " ", sizeof(strbuf) - strlen(strbuf) - 1);

	    len = strlen(strbuf);

	    if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "       ");
	    else if( ap_cur->security & ENC_CCMP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "CCMP   ");
	    else if( ap_cur->security & ENC_WRAP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "WRAP   ");
	    else if( ap_cur->security & ENC_TKIP   ) snprintf( strbuf+len, sizeof(strbuf)-len, "TKIP   ");
	    else if( ap_cur->security & ENC_WEP104 ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP104 ");
	    else if( ap_cur->security & ENC_WEP40  ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP40  ");
	    else if( ap_cur->security & ENC_WEP    ) snprintf( strbuf+len, sizeof(strbuf)-len, "WEP    ");

	    len = strlen(strbuf);

	    if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ) snprintf( strbuf+len, sizeof(strbuf)-len, "   ");
	    else if( ap_cur->security & AUTH_MGT   ) snprintf( strbuf+len, sizeof(strbuf)-len, "MGT");
	    else if( ap_cur->security & AUTH_PSK   ) {
			if( ap_cur->security & STD_WEP )
				snprintf( strbuf+len, sizeof(strbuf)-len, "SKA");
			else
				snprintf( strbuf+len, sizeof(strbuf)-len, "PSK");
	    } else if( ap_cur->security & AUTH_OPN   ) snprintf( strbuf+len, sizeof(strbuf)-len, "OPN");

	    len = strlen(strbuf);

	    if (G.show_uptime) {
	    	snprintf(strbuf+len, sizeof(strbuf)-len, " %14s", parse_timestamp(ap_cur->timestamp));
	    	len = strlen(strbuf);
	    }

	    strbuf[ws_col-1] = '\0';

	    if(G.selection_ap && ((num_ap) == G.selected_ap)) {
			if(G.mark_cur_ap) {
				if(ap_cur->marked == 0) {
					ap_cur->marked = 1;
				} else {
					ap_cur->marked_color++;
					if(ap_cur->marked_color > (TEXT_MAX_COLOR-1)) {
						ap_cur->marked_color = 1;
						ap_cur->marked = 0;
					}
				}
				G.mark_cur_ap = 0;
			}
			textstyle(TEXT_REVERSE);
			memcpy(G.selected_bssid, ap_cur->bssid, 6);
	    }

	    if(ap_cur->marked) {
			textcolor_fg(ap_cur->marked_color);
	    }

	    fprintf(stderr, "%s", strbuf);

	    if( ws_col > (columns_ap - 4) ) {
			memset( strbuf, 0, sizeof( strbuf ) );
			if (G.show_wps) {
		    if (ap_cur->wps.state != 0xFF)
		    {
		        if (ap_cur->wps.ap_setup_locked) // AP setup locked
		            snprintf(strbuf, sizeof(strbuf)-1, "Locked");
		        else
		        {
		            snprintf(strbuf, sizeof(strbuf)-1, "%d.%d", ap_cur->wps.version >> 4, ap_cur->wps.version & 0xF); // Version
		            if (ap_cur->wps.meth) // WPS Config Methods
		            {
		                char tbuf[64];
		                memset( tbuf, '\0', sizeof(tbuf) );
		                int sep = 0;
#define T(bit, name) do {                       \
    if (ap_cur->wps.meth & (1<<bit)) {          \
        if (sep)                                \
            strcat(tbuf, ",");                  \
        sep = 1;                                \
        strncat(tbuf, name, (64-strlen(tbuf))); \
    } } while (0)
		                T(0, "USB");     // USB method
		                T(1, "ETHER");   // Ethernet
		                T(2, "LAB");     // Label
		                T(3, "DISP");    // Display
		                T(4, "EXTNFC");  // Ext. NFC Token
		                T(5, "INTNFC");  // Int. NFC Token
		                T(6, "NFCINTF"); // NFC Interface
		                T(7, "PBC");     // Push Button
		                T(8, "KPAD");    // Keypad
		                snprintf(strbuf+strlen(strbuf), sizeof(strbuf)-strlen(strbuf), " %s", tbuf);
#undef T
		            }
		        }
		    }
		    else {
		        snprintf(strbuf, sizeof(strbuf)-1, " ");
		    }
			
		    if (G.maxsize_wps_seen <= strlen(strbuf))
				G.maxsize_wps_seen = strlen(strbuf);
				else // write spaces (32)
				memset( strbuf+strlen(strbuf), 32,  (G.maxsize_wps_seen - strlen(strbuf))  );
			}
			
			if(ap_cur->essid[0] != 0x00)
			{
				if (G.show_wps)
				snprintf( strbuf + G.maxsize_wps_seen, sizeof(strbuf)-G.maxsize_wps_seen,
					"  %s", ap_cur->essid );
				else
				snprintf( strbuf,  sizeof( strbuf ) - 1,
					"%s", ap_cur->essid );
			}
			else
			{
				if (G.show_wps)
				snprintf( strbuf + G.maxsize_wps_seen, sizeof(strbuf)-G.maxsize_wps_seen,
					"  <length:%3d>%s", ap_cur->ssid_length, "\x00" );
				else
				snprintf( strbuf,  sizeof( strbuf ) - 1,
					"<length:%3d>%s", ap_cur->ssid_length, "\x00" );
			}

			if (G.show_manufacturer) {

				if (G.maxsize_essid_seen <= strlen(strbuf))
					G.maxsize_essid_seen = strlen(strbuf);
				else // write spaces (32)
					memset( strbuf+strlen(strbuf), 32,  (G.maxsize_essid_seen - strlen(strbuf))  );

				if (ap_cur->manuf == NULL)
					ap_cur->manuf = get_manufacturer(ap_cur->bssid[0], ap_cur->bssid[1], ap_cur->bssid[2]);

				snprintf( strbuf + G.maxsize_essid_seen , sizeof(strbuf)-G.maxsize_essid_seen, "  %s", ap_cur->manuf );
			}

			// write spaces (32) until the end of column
			memset( strbuf+strlen(strbuf), 32, ws_col - (columns_ap - 4 ) );

			// end the string at the end of the column
			strbuf[ws_col - (columns_ap - 4)] = '\0';

			fprintf( stderr, "  %s", strbuf );
	    }

	    fprintf( stderr, "\n" );

	    if( (G.selection_ap && ((num_ap) == G.selected_ap)) || (ap_cur->marked) ) {
			textstyle(TEXT_RESET);
	    }

	    ap_cur = ap_cur->prev;
	}

		/* print some informations about each detected station */

		nlines += 3;

		if( nlines >= (ws_row-1) )
			return;

		memset( strbuf, ' ', ws_col - 1 );
		strbuf[ws_col - 1] = '\0';
		fprintf( stderr, "%s\n", strbuf );
    }

    if(G.show_sta) {
	memcpy( strbuf, " BSSID              STATION "
		"           PWR   Rate    Lost    Frames  Probes", columns_sta );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	memset( strbuf, ' ', ws_col - 1 );
	strbuf[ws_col - 1] = '\0';
	fprintf( stderr, "%s\n", strbuf );

	ap_cur = G.ap_end;

	num_sta = 0;

	while( ap_cur != NULL )
	{
	    if( ap_cur->nb_pkt < 2 ||
		time( NULL ) - ap_cur->tlast > G.berlin )
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    // Don't filter unassociated clients by ESSID
	    if(memcmp(ap_cur->bssid, BROADCAST, 6) && is_filtered_essid(ap_cur->essid))
	    {
		ap_cur = ap_cur->prev;
		continue;
	    }

	    if( nlines >= (ws_row-1) )
		return;

	    st_cur = G.st_end;

	    if(G.selection_ap && (memcmp(G.selected_bssid, ap_cur->bssid, 6)==0)) {
		textstyle(TEXT_REVERSE);
	    }

	    if(ap_cur->marked) {
		textcolor_fg(ap_cur->marked_color);
	    }

	    while( st_cur != NULL )
	    {
		if( st_cur->base != ap_cur ||
		    time( NULL ) - st_cur->tlast > G.berlin )
		{
		    st_cur = st_cur->prev;
		    continue;
		}

		if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) && G.asso_client )
		{
		    st_cur = st_cur->prev;
		    continue;
		}

		num_sta++;

		if(G.start_print_sta > num_sta)
		    continue;

		nlines++;

		if( ws_row != 0 && nlines >= ws_row )
		    return;

		if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) )
		    fprintf( stderr, " (not associated) " );
		else
		    fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
			    ap_cur->bssid[0], ap_cur->bssid[1],
			    ap_cur->bssid[2], ap_cur->bssid[3],
			    ap_cur->bssid[4], ap_cur->bssid[5] );

		fprintf( stderr, "  %02X:%02X:%02X:%02X:%02X:%02X",
			st_cur->stmac[0], st_cur->stmac[1],
			st_cur->stmac[2], st_cur->stmac[3],
			st_cur->stmac[4], st_cur->stmac[5] );

		fprintf( stderr, "  %3d ", st_cur->power    );
		fprintf( stderr, "  %2d", st_cur->rate_to/1000000  );
		fprintf( stderr,  "%c", (st_cur->qos_fr_ds) ? 'e' : ' ');
		fprintf( stderr,  "-%2d", st_cur->rate_from/1000000);
		fprintf( stderr,  "%c", (st_cur->qos_to_ds) ? 'e' : ' ');
		fprintf( stderr, "  %4d", st_cur->missed   );
		fprintf( stderr, " %8lu", st_cur->nb_pkt   );

		if( ws_col > (columns_sta - 6) )
		{
		    memset( ssid_list, 0, sizeof( ssid_list ) );

		    for( i = 0, n = 0; i < NB_PRB; i++ )
		    {
			if( st_cur->probes[i][0] == '\0' )
			    continue;

			snprintf( ssid_list + n, sizeof( ssid_list ) - n - 1,
				"%c%s", ( i > 0 ) ? ',' : ' ',
				st_cur->probes[i] );

			n += ( 1 + strlen( st_cur->probes[i] ) );

			if( n >= (int) sizeof( ssid_list ) )
			    break;
		    }

		    memset( strbuf, 0, sizeof( strbuf ) );
		    snprintf( strbuf,  sizeof( strbuf ) - 1,
			    "%-256s", ssid_list );
		    strbuf[ws_col - (columns_sta - 6)] = '\0';
		    fprintf( stderr, " %s", strbuf );
		}

		fprintf( stderr, "\n" );

		st_cur = st_cur->prev;
	    }

	    if( (G.selection_ap && (memcmp(G.selected_bssid, ap_cur->bssid, 6)==0)) || (ap_cur->marked) ) {
		textstyle(TEXT_RESET);
	    }

	    ap_cur = ap_cur->prev;
	}
    }

    if(G.show_ack)
    {
        /* print some informations about each unknown station */

        nlines += 3;

        if( nlines >= (ws_row-1) )
            return;

        memset( strbuf, ' ', ws_col - 1 );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        memcpy( strbuf, " MAC       "
                "          CH PWR    ACK ACK/s    CTS RTS_RX RTS_TX  OTHER", columns_na );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        memset( strbuf, ' ', ws_col - 1 );
        strbuf[ws_col - 1] = '\0';
        fprintf( stderr, "%s\n", strbuf );

        na_cur = G.na_1st;

        while( na_cur != NULL )
        {
            if( time( NULL ) - na_cur->tlast > 120 )
            {
                na_cur = na_cur->next;
                continue;
            }

            if( nlines >= (ws_row-1) )
                return;

            nlines++;

            if( ws_row != 0 && nlines >= ws_row )
                return;

            fprintf( stderr, " %02X:%02X:%02X:%02X:%02X:%02X",
                    na_cur->namac[0], na_cur->namac[1],
                    na_cur->namac[2], na_cur->namac[3],
                    na_cur->namac[4], na_cur->namac[5] );

            fprintf( stderr, "  %3d", na_cur->channel  );
            fprintf( stderr, " %3d", na_cur->power  );
            fprintf( stderr, " %6d", na_cur->ack );
            fprintf( stderr, "  %4d", na_cur->ackps );
            fprintf( stderr, " %6d", na_cur->cts );
            fprintf( stderr, " %6d", na_cur->rts_r );
            fprintf( stderr, " %6d", na_cur->rts_t );
            fprintf( stderr, " %6d", na_cur->other );

            fprintf( stderr, "\n" );

            na_cur = na_cur->next;
        }
    }
}

int get_ap_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;

    int num_ap;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_ap = 0;

    while( ap_cur != NULL )
    {
        /* skip APs with only one packet, or those older than 2 min.
         * always skip if bssid == broadcast */

        if( ap_cur->nb_pkt < 2 || time( NULL ) - ap_cur->tlast > G.berlin ||
            memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

	num_ap++;
	ap_cur = ap_cur->prev;
    }

    return num_ap;
}

int get_sta_list_count() {
    time_t tt;
    struct tm *lt;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;

    int num_sta;

    tt = time( NULL );
    lt = localtime( &tt );

    ap_cur = G.ap_end;

    num_sta = 0;

    while( ap_cur != NULL )
    {
        if( ap_cur->nb_pkt < 2 ||
            time( NULL ) - ap_cur->tlast > G.berlin )
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        // Don't filter unassociated clients by ESSID
        if(memcmp(ap_cur->bssid, BROADCAST, 6) && is_filtered_essid(ap_cur->essid))
        {
            ap_cur = ap_cur->prev;
            continue;
        }

        st_cur = G.st_end;

        while( st_cur != NULL )
        {
            if( st_cur->base != ap_cur ||
                time( NULL ) - st_cur->tlast > G.berlin )
            {
                st_cur = st_cur->prev;
                continue;
            }

            if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) && G.asso_client )
            {
                st_cur = st_cur->prev;
                continue;
            }

	    num_sta++;

            st_cur = st_cur->prev;
        }

        ap_cur = ap_cur->prev;
    }
    return num_sta;
}

char *dump_na_list() {
		struct NA_info *na_cur;
        char strbuff[512] = {0};
        struct json_object * jarray_na = json_object_new_array();

        pthread_mutex_lock(&(G.mx_print));
        na_cur = G.na_1st;
        while(na_cur != NULL) {
                if(time(NULL) - na_cur->tlast > 120) {
                        na_cur = na_cur->next;
                        continue;
                }

                struct json_object *jobj = json_object_new_object();

                memset(strbuff,'\x0',sizeof(strbuff));
                snprintf(strbuff,sizeof(strbuff),"%02X:%02X:%02X:%02X:%02X:%02X",
                                                na_cur->namac[0],na_cur->namac[1],
                                                na_cur->namac[2],na_cur->namac[3],
                                                na_cur->namac[4],na_cur->namac[5]);
                json_object_object_add(jobj,"namac",json_object_new_string(strbuff));

                json_object_object_add(jobj,"channel",json_object_new_int(na_cur->channel));
                json_object_object_add(jobj,"power",json_object_new_int(na_cur->power));
                json_object_object_add(jobj,"ack",json_object_new_int(na_cur->ack));
                json_object_object_add(jobj,"ackps",json_object_new_int(na_cur->ackps));
                json_object_object_add(jobj,"cts",json_object_new_int(na_cur->cts));
                json_object_object_add(jobj,"rts_r",json_object_new_int(na_cur->rts_r));
                json_object_object_add(jobj,"rts_t",json_object_new_int(na_cur->rts_t));
                json_object_object_add(jobj,"other",json_object_new_int(na_cur->other));

                json_object_array_add(jarray_na,jobj);
                na_cur = na_cur->next;
        }
        pthread_mutex_unlock(&(G.mx_print));

        char *ret = strdup(json_object_to_json_string(jarray_na));
		json_object_put(jarray_na);
        if(!ret) {
                printf("malloc mem failed!\n");
                exit(1);
        }
        else
                return ret;
}

char *dump_sta_list() {
		int i,n;
        struct AP_info *ap_cur;
        struct ST_info *st_cur;
        char strbuff[512] = {0};
        char ssid_list[512] = {0};
	
        struct json_object *jarray_sta = json_object_new_array();

        pthread_mutex_lock( &(G.mx_print));
        ap_cur = G.ap_end;
        while(ap_cur != NULL) {
			if(ap_cur->nb_pkt < 2 || time(NULL) - ap_cur->tlast > G.berlin) {
				ap_cur = ap_cur->prev;
				continue;
			}

			if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0)) {
				ap_cur = ap_cur->prev;
				continue;
			}

			if(memcmp(ap_cur->bssid,BROADCAST,6) && is_filtered_essid(ap_cur->essid)) {
				ap_cur = ap_cur->prev;
				continue;
			}

			st_cur = G.st_end;
			while(st_cur != NULL) {
				if(st_cur->base != ap_cur || time(NULL) - st_cur->tlast > G.berlin) {
					st_cur = st_cur->prev;
					continue;
				}

				if(!memcmp(ap_cur->bssid,BROADCAST,6)) {
					st_cur = st_cur->prev;
					continue;
				}

				struct json_object * jobj = json_object_new_object();

				memset(strbuff,'\x0',sizeof(strbuff));

				snprintf(strbuff,sizeof(strbuff),"%02X:%02X:%02X:%02X:%02X:%02X",
							ap_cur->bssid[0],ap_cur->bssid[1],
							ap_cur->bssid[2],ap_cur->bssid[3],
							ap_cur->bssid[4],ap_cur->bssid[5]);

				json_object_object_add(jobj,"bssid",json_object_new_string(strbuff));
				json_object_object_add(jobj,"essid",json_object_new_string(ap_cur->essid));		

				memset(strbuff,'\x0',sizeof(strbuff));
				snprintf(strbuff,sizeof(strbuff),"%02X:%02X:%02X:%02X:%02X:%02X",
							st_cur->stmac[0],st_cur->stmac[1],
							st_cur->stmac[2],st_cur->stmac[3],
							st_cur->stmac[4],st_cur->stmac[5]);
				json_object_object_add(jobj,"sta_mac",json_object_new_string(strbuff));


				json_object_object_add(jobj,"power",json_object_new_int(st_cur->power));
				json_object_object_add(jobj,"rate_to",json_object_new_int(st_cur->rate_to/1000000));


				memset(strbuff,'\x0',sizeof(strbuff));
				snprintf(strbuff,sizeof(strbuff),"%c",(st_cur->qos_fr_ds ? 'e' : ' '));
				json_object_object_add(jobj,"qos_fr_ds",json_object_new_string(strbuff));


				memset(strbuff,'\x0',sizeof(strbuff));
				snprintf(strbuff,sizeof(strbuff),"-%2d",st_cur->rate_from/1000000);
				json_object_object_add(jobj,"rate_from",json_object_new_string(strbuff));


				memset(strbuff,'\x0',sizeof(strbuff));
				snprintf(strbuff,sizeof(strbuff),"%c",(st_cur->qos_to_ds ? 'e' : ' '));
				json_object_object_add(jobj,"qos_to_ds",json_object_new_string(strbuff));

				json_object_object_add(jobj,"missed",json_object_new_int(st_cur->missed));
				json_object_object_add(jobj,"nb_pkt",json_object_new_int64(st_cur->nb_pkt));

				memset(ssid_list,'\x0',sizeof(ssid_list));
				for(i=0,n=0;i < NB_PRB; i++) {
					if(st_cur->probes[i][0] == '\0')
						continue;

					snprintf(ssid_list + n,sizeof(ssid_list)-n-1,"%c%s",(i>0) ? ',' : ' ',st_cur->probes[i]);
					n += (1 + strlen(st_cur->probes[i]));

					if(n >= (int)sizeof(ssid_list)) {
						break;
					}
				}

				memset(strbuff,'\x0',sizeof(strbuff));
				snprintf(strbuff,sizeof(strbuff)-1,"%-32s",ssid_list);
				json_object_object_add(jobj,"ssid",json_object_new_string(strbuff));

				json_object_array_add(jarray_sta,jobj);
				st_cur = st_cur->prev;
			}
        	ap_cur = ap_cur->prev;
        }
        pthread_mutex_unlock(&(G.mx_print));
	
		char * ret = strdup(json_object_to_json_string(jarray_sta));
		json_object_put(jarray_sta);
        if(!ret) {
			printf("malloc mem failed!\n");
			exit(1);
        }
        else
			return ret;
}

char *dump_ap_list() {
        char strbuff[512] = {0};
        struct AP_info *ap_cur;
	
        struct json_object *jarray_ap = json_object_new_array();

        pthread_mutex_lock( &(G.mx_print) );

        ap_cur = G.ap_end;
        while (ap_cur != NULL) {
			if(ap_cur->nb_pkt < 2 || time(NULL) - ap_cur->tlast > G.berlin || memcmp(ap_cur->bssid,BROADCAST,6) == 0) {
				ap_cur = ap_cur->prev;
				continue;
			}

			if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0)) {
				ap_cur = ap_cur->prev;
				continue;
			}

			if(is_filtered_essid(ap_cur->essid)) {
				ap_cur = ap_cur->prev;
				continue;
			}

			struct json_object *jobj = json_object_new_object();

			memset(strbuff,'\x0',sizeof(strbuff));
			snprintf(strbuff,sizeof(strbuff),"%02X:%02X:%02X:%02X:%02X:%02X",
							ap_cur->bssid[0],ap_cur->bssid[1],
							ap_cur->bssid[2],ap_cur->bssid[3],
							ap_cur->bssid[4],ap_cur->bssid[5]);
			json_object_object_add(jobj,"bssid",json_object_new_string(strbuff));


			json_object_object_add(jobj,"PWR",json_object_new_int(ap_cur->avg_power));
			json_object_object_add(jobj,"QUAL",json_object_new_int(ap_cur->rx_quality));
			json_object_object_add(jobj,"Beacons",json_object_new_int64(ap_cur->nb_bcn));
			json_object_object_add(jobj,"Datas",json_object_new_int64(ap_cur->nb_data));
			json_object_object_add(jobj,"Datasps",json_object_new_int(ap_cur->nb_dataps));
			json_object_object_add(jobj,"CH",json_object_new_int(ap_cur->channel));
			json_object_object_add(jobj,"MB",json_object_new_int(ap_cur->max_speed));

			memset(strbuff,'\x0',sizeof(strbuff));
			snprintf(strbuff,sizeof(strbuff),"%c",((ap_cur->security & STD_QOS) ? 'e' : ' '));
			json_object_object_add(jobj,"SEC",json_object_new_string(strbuff));

			memset(strbuff,'\x0',sizeof(strbuff));
			snprintf(strbuff,sizeof(strbuff),"%c",((ap_cur->preamble) ? '.' : ' '));
			json_object_object_add(jobj,"Preamble",json_object_new_string(strbuff));


			memset(strbuff,'\x0',sizeof(strbuff));
			if((ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0)
					snprintf(strbuff,sizeof(strbuff),"    ");
			else if(ap_cur->security & STD_WPA2)
					snprintf(strbuff,sizeof(strbuff),"WPA2");
			else if(ap_cur->security & STD_WPA )
					snprintf(strbuff,sizeof(strbuff),"WPA");
			else if(ap_cur->security & STD_WEP )
					snprintf(strbuff,sizeof(strbuff),"WEP");
			else if(ap_cur->security & STD_OPN)
				snprintf(strbuff,sizeof(strbuff),"OPN");
			json_object_object_add(jobj,"ENC",json_object_new_string(strbuff));


			memset(strbuff,'\x0',sizeof(strbuff));
			if((ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0)
					snprintf(strbuff,sizeof(strbuff),"    ");
			else if(ap_cur->security & ENC_CCMP)
					snprintf(strbuff,sizeof(strbuff),"CCMP");
			else if(ap_cur->security & ENC_WRAP)
					snprintf(strbuff,sizeof(strbuff),"WRAP");
			else if(ap_cur->security & ENC_TKIP)
					snprintf(strbuff,sizeof(strbuff),"TKIP");
			else if(ap_cur->security & ENC_WEP104)
					snprintf(strbuff,sizeof(strbuff),"WEP104");
			else if(ap_cur->security & ENC_WEP40)
					snprintf(strbuff,sizeof(strbuff),"WEP40");
			else if(ap_cur->security & ENC_WEP)
					snprintf(strbuff,sizeof(strbuff),"WEP");
			json_object_object_add(jobj,"CIPHER",json_object_new_string(strbuff));


			memset(strbuff,'\x0',sizeof(strbuff));
			if((ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0)
				snprintf(strbuff,sizeof(strbuff),"    ");
			else if(ap_cur->security & AUTH_MGT)
				snprintf(strbuff,sizeof(strbuff),"MGT");
			else if(ap_cur->security & AUTH_PSK) {
				if(ap_cur->security & STD_WEP)
					snprintf(strbuff,sizeof(strbuff),"SKA");
				else 
					snprintf(strbuff,sizeof(strbuff),"PSK");
			}    
			else if(ap_cur->security & AUTH_OPN) {
				snprintf(strbuff,sizeof(strbuff),"OPN");
			}    
			json_object_object_add(jobj,"AUTH",json_object_new_string(strbuff));


			memset(strbuff,'\x0',sizeof(strbuff));
			snprintf(strbuff,sizeof(strbuff),"%14s",parse_timestamp(ap_cur->timestamp));
			json_object_object_add(jobj,"UPTIME",json_object_new_string(strbuff));


			memset(strbuff,'\x0',sizeof(strbuff));
			if(ap_cur->essid[0] != 0x00) {
				snprintf(strbuff,sizeof(strbuff),"%s",ap_cur->essid);
			} else {
				snprintf(strbuff,sizeof(strbuff),"<length:%3d>%s",ap_cur->ssid_length,"\x00");
			}    
			json_object_object_add(jobj,"ESSID",json_object_new_string(strbuff));
			memset(strbuff,'\x0',sizeof(strbuff));
			if(ap_cur->manuf == NULL) {	
				ap_cur->manuf = get_manufacturer(ap_cur->bssid[0],ap_cur->bssid[1],ap_cur->bssid[2]);
			}
			snprintf(strbuff,sizeof(strbuff),"%s",ap_cur->manuf);
			json_object_object_add(jobj,"MANUF",json_object_new_string(strbuff));


			json_object_array_add(jarray_ap,jobj);

			ap_cur = ap_cur->prev;
        }
        pthread_mutex_unlock( &(G.mx_print) );

        char *ret = strdup(json_object_to_json_string(jarray_ap));
        json_object_put(jarray_ap);
	   
	    if(!ret) {
                printf("malloc mem failed!\n");
                exit(1);
        }
        else
                return ret; 
}
