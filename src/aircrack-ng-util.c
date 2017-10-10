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
    }
}
