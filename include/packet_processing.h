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
#include "../include/telnet.h"
#include "../include/dhcp.h"
#include "../include/dns.h"
#include "../include/utils.h"

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

/*
  Traite la couche Réseau
*/
void process_network_layer(const u_char* , uint32_t,int*, int );
/*
  Traite la couche transport
*/
int process_transport_layer(const u_char* , int, int* , int* , int*, int );
/*
  Traite la couche application en appelant find_application
*/
void process_app(const u_char*, int , int , int, int );

/*
  Match les ports afin de trouver l'application associé, 
  et lance la fonction appropriée
*/
int find_application(const u_char*, int , int , int,int );


#endif
