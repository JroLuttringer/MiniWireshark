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
void process_ethernet(const u_char* , int*,int );
char* ethernet_type(const struct ether_header*);
void ethaddr2hexa();

#endif