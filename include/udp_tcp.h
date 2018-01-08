#ifndef __UDP_TCP_H__
#define __UDP_TCP_H__

#include <stdio.h>  // printf
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <arpa/inet.h> 
#include "../include/utils.h"

/*
  Affiche les informations UDP, suivant le niveau de verbosité.
  Utilise trois pointeurs pour renvoyer les ports utilisés et
  la taille de l'en tête
*/
void process_udp(const u_char* , int* , int* , int*,int );

/*
  Affiche les informations TCP, suivant le niveau de verbosité.
  Utilise trois pointeurs pour renvoyer les ports utilisés et
  la taille de l'en tête
*/
void process_tcp(const u_char* , int*, int* , int*,int);

#endif