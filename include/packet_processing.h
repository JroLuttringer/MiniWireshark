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
#include "../include/my_icmp.h"
#include "../include/udp_tcp.h"
#include <ctype.h> // for isalnum
#include "../include/arp.h"
#include "../include/http_imap_pop_smtp_ftp.h"

#define MAX_BYTE     15000
#define PROMISC_MODE 1
#define UDP          17
#define TCP          6
#define ICMP         1

#define POP    110
#define IMAP   143
#define SMTP   25
#define SMTPS  587
#define HTTP   80
#define DNS    53
#define TELNET 23
#define DHCP   67
#define FTPD   20
#define FTPC   21    

#define REQUEST 999



void print_ascii(const u_char*, int length);
void got_packet(u_char*, const struct pcap_pkthdr*, const u_char*);
void print_data(const u_char*);
#endif