#ifndef __ICMP_H__
#define __ICMP_H__

#include <netinet/ip_icmp.h>
#include <stdio.h>
#include "../include/utils.h"
#include <arpa/inet.h>
void process_icmp(const u_char*);

#endif