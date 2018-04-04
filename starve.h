//
// Created by adam on 3/22/18.
//

#ifndef DHCP_STARVATION_STARVE_H
#define DHCP_STARVATION_STARVE_H

#include <stdio.h>
#include <stdlib.h>
//#include <locale.h>
//#include <string.h>
//#include <errno.h>
//#include <unistd.h>
//#include <sys/time.h>
//#include <sys/ioctl.h>
//#include <fcntl.h>
//#include <getopt.h>
//#include <sys/socket.h>
//#include <sys/types.h>
//#include <netdb.h>
//#include <netinet/in.h>
//#include <net/if.h>
//#include <arpa/inet.h>

#define MAX_DHCP_CHADDR_LENGTH           16
#define MAX_DHCP_SNAME_LENGTH            64
#define MAX_DHCP_FILE_LENGTH             128
#define MAX_DHCP_OPTIONS_LENGTH          312    //minimum

typedef struct dhcp_packet_struct {
    u_int8_t op;                    // packet type
    u_int8_t htype;                 // hardware address type
    u_int8_t hlen;                  // hardware address len
    u_int8_t hops;
    u_int32_t xid;                  // random transaction id
    u_int16_t secs;                 // seconds since began aquisition
    u_int16_t flags;
    struct in_addr ciaddr;          // IP, not used
    struct in_addr yiaddr;          // client IP
    struct in_addr siaddr;          // IP address of next server to use in bootstrap
    struct in_addr giaddr;          // Relay agent IP address
    uint8_t chaddr[MAX_DHCP_CHADDR_LENGTH];      // Client hardware address.
    uint8_t sname[MAX_DHCP_SNAME_LENGTH];      // Optional server host name
    uint8_t file[MAX_DHCP_FILE_LENGTH];        // Boot file name
    uint8_t options[MAX_DHCP_OPTIONS_LENGTH];  // options
} dhcp_packet;



#endif //DHCP_STARVATION_STARVE_H
