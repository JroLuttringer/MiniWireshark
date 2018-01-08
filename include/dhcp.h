#ifndef __DHCP_H__
#define __DHCP_H__

#include <netinet/ether.h>
#include <arpa/inet.h>
#include "../include/bootp.h"
#include <stdio.h>
#include "../include/utils.h"


void process_bootp(const u_char*,int);

void print_dhcp_type(int);

void print_dhcp_option(const u_char* ,int,int);

void process_dhcp(const u_char*,int );

int test_dhcp(const u_char*);



#endif
