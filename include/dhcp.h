#ifndef __DHCP_H__
#define __DHCP_H__

#include <netinet/ether.h>
#include <arpa/inet.h>
#include "../include/bootp.h"
#include <stdio.h>
#include "../include/utils.h"

/*
  Affiche les informations BOOTP dans 
  le paquet passé en argument, suivant
  le niveau de verbosité voulu
*/
void process_bootp(const u_char*,int);

/*
  Affiche le type DHCP associé à l'entier
  passé en argument
*/
void print_dhcp_type(int);

/*
  Affiche l'option DHCP à l'indexe i 
  du paquet, suivant le niveau de verbosité voulu
*/
void print_dhcp_option(const u_char* ,int,int);

/*
  Affiche les informations DHCP du paquet
  suivant le niveau de verbosité associé
*/

void process_dhcp(const u_char*,int );


/*
  Test si le magic cookie 
  indique la présence de DHCP ou non
*/
int test_dhcp(const u_char*);



#endif
