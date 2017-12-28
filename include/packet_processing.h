#ifndef __PACKET_PROCESSING_H__
#define __PACKET_PROCESSING_H__

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>            // for strdup
#include <unistd.h>            // for getopt()
#include "../include/check.h"  // Check & exit if error
#include "../include/my_ethernet.h"
#include "../include/my_ip.h"
#include "../include/udp_tcp.h"

#define MAX_BYTE 15000
#define PROMISC_MODE 1
#define UDP 17
#define TCP 6
#define ICMP 1

void got_packet(u_char*, const struct pcap_pkthdr*, const u_char*);

#endif