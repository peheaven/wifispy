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
