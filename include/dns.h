#ifndef __DNS_H__
#define __DNS_H__

#include <arpa/nameser_compat.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <ctype.h> // for isprint
#include "../include/utils.h"


#define DNSQUERY 0
#define DNSIQUERY 1
#define DNSSSR 2
// 3 is unassigned
#define DNSNOTIFY 4
#define DNSUPDATE 5


#define PTRMASK 0b11000000
#define PTRINDEXMASK 0b0011111111111111
#define PTRVALUE 192

#define QSTLEN 4
#define RSRLEN 10

#define DNSNOERROR 0
#define DNSFORMERR 1
#define DNSSERVFAIL 2
#define DNSNXDOMAIN 3
#define DNSNOTIMP 4
#define DNSREFUSED 5
#define DNSYXDOMAIN 6
#define DNSYXRRSET 7
#define DNSBADCOOKIE 23

struct qst {
  u_int16_t type;
  u_int16_t clss;
};

struct resource {
  u_int16_t type;
  u_int16_t clss;
  u_int32_t ttl;
  u_int16_t length;
};

/*
  Affiche en texte le Rcode
  DNS passé en argument
*/
void display_rcode(int);

/*
  Fonction permettant d'afficher le nom DNS
  Les deux pointeurs représentent le paquet entier,
  et le début du nom dans le paquet 
  La fonction est récursive
*/
int get_name(const u_char*, const u_char*  );

/*
  Fonction affichant les informations DNS
  contenues dans le paquet suivant le niveau de verbosité voulu
*/
void process_dns(const u_char*,int );

/* 
  Affiche en texte l'opcode passé en 
  argument
*/
void print_dns_opcode(int);

#endif
