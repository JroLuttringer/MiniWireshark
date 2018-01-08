#ifndef __ARP_H__
#define __ARP_H__

#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "../include/packet_processing.h"
#include "../include/utils.h"

/*
 Affiche les info du protocole ARP contenu dans le paquet
 suivant le niveau de verbosité voulue
*/
void process_arp(const u_char*,int);

/*
  Affiche en texte l'opcode ARP associé à l'entier passé en argument
*/
void print_opcode(int);

#endif