#ifndef __UDP_TCP_H__
#define __UDP_TCP_H__

#include <stdio.h>  // printf
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> 
#include "../include/utils.h"

void process_udp(const u_char* , int* , int* , int* );

void process_tcp(const u_char* , int*, int* , int*);

#endif