#ifndef __MY_ETHERNET_H__
#define __MY_ETHERNET_H__

#include <arpa/inet.h>  // ntohs
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdio.h>  // printf

#define ETH_ADDR_LEN 6
#define UDP 17
#define TCP 6
#define ICMP 1

uint32_t process_ethernet(const u_char*);
char* ethernet_type(const struct ether_header*);
void ethaddr2hexa();

#endif