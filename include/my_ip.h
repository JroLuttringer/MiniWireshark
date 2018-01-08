#ifndef __MY_IP_H__
#define __MY_IP_H__

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include "../include/utils.h"

#define RESERVED 0b10000000
#define DONTFRAG 0b01000000
#define MOREFRAG 0b00100000
#define FRAGOFF 0b0000000011111111

/*
  Affiche les informations IP
  contenues dans le paquet suivant le niveau de verbosité
*/
int process_ip(const u_char*,int);

/*
  Affiche le nom de l'application 
  de la couche suivante
*/
char* protocol_name(int);
#endif
