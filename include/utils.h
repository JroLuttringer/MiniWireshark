#ifndef __UTILS_H__
#define __UTILS_H__

#define APP_SPACE_HDR 6
#define TSP_SPACE_HDR 4
#define IP_SPACE_HDR 2
#define APP_SPACE 8
#define TSP_SPACE 6
#define IP_SPACE 4

#include <stdio.h>
#include <arpa/inet.h> 
#include <pcap/pcap.h>
#include <ctype.h>

/* Affiche un apercu du paquet en hexa et en ascii */
void packet_to_hexa(const u_char* , const struct pcap_pkthdr*);

/* Affiche "int" octet en ascii */
void print_ascii(const u_char* , int );

/* Aperçu des données en fin de paquet */
void print_data(const u_char* ) ;

#endif