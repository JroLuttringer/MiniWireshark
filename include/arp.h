#ifndef __ARP_H__
#define __ARP_H__

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <arpa/inet.h>

void process_arp(const u_char*);


#endif