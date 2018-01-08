#ifndef __DHCP_H__
#define __DHCP_H__

#include <netinet/ether.h>
#include <arpa/inet.h>
#include "../include/bootp.h"
#include <stdio.h>
#include "../include/utils.h"


void process_bootp(const u_char* packet);


#endif
