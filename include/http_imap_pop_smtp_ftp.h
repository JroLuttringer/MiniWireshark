#ifndef __HTTP_H__
#define __HTTP_H__

#include "../include/packet_processing.h"
#include "../include/utils.h"

void process_http(const u_char*,int, int);
void process_imap(const u_char*,int, int);
void process_pop(const u_char*,int, int);
void process_smtp(const u_char*,int, int);
void process_ftp(const u_char*,int, int);
#endif 