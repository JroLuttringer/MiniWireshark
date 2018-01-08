#ifndef __ICMP_H__
#define __ICMP_H__

#include <netinet/ip_icmp.h>
#include <stdio.h>
#include "../include/utils.h"
#include <arpa/inet.h>

/* 
  Affiche les informations ICMP contenues 
  dans le paquet suivant le niveau de verbosité
  voulue
*/
void process_icmp(const u_char*,int);

/*
  Affiche en texte le type ICMP
  (Echo request, response , etc)
*/
void print_icmp_type(int);

#endif