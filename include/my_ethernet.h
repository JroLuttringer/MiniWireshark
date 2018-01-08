#ifndef __MY_ETHERNET_H__
#define __MY_ETHERNET_H__

#include <arpa/inet.h>  // ntohs
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>  // printf
#include "../include/utils.h"


#define ETH_ADDR_LEN 6
#define UDP 17
#define TCP 6
#define ICMP 1

/* Affiche les information Ethernet contenue dans le paquet
  prend également en argument un pointeur afin de retourner
  le type de la couche suivant (IP ou autre)
*/
void process_ethernet(const u_char* , int*,int );

/*
  Affiche en texte le type associé
  */
char* ethernet_type(const struct ether_header*);

/*
  Affiche en hexa l'addresse MAC passé en argument
*/
void ethaddr2hexa(const uint8_t* addr);

#endif