#ifndef __HTTP_H__
#define __HTTP_H__

#include "../include/packet_processing.h"
#include "../include/utils.h"

/*
  Affiche les informations HTTP contenue dans
  le paquet, suivant le niveau de verbosité voulue
  La fonction demande également le nombre d'octet
  à afficher, et un booléen indiquant si le paquet
  est une réponse ou une reqûete
*/
void process_http(const u_char*,int, int,int);

/*
  Affiche les informations IMAP contenue dans
  le paquet, suivant le niveau de verbosité voulue
  La fonction demande également le nombre d'octet
  à afficher, et un booléen indiquant si le paquet
  est une réponse ou une reqûete
*/
void process_imap(const u_char*,int, int,int);

/*
  Affiche les informations POP contenue dans
  le paquet, suivant le niveau de verbosité voulue
  La fonction demande également le nombre d'octet
  à afficher, et un booléen indiquant si le paquet
  est une réponse ou une reqûete
*/
void process_pop(const u_char*,int, int,int);

/*
  Affiche les informations SMTP contenue dans
  le paquet, suivant le niveau de verbosité voulue
  La fonction demande également le nombre d'octet
  à afficher, et un booléen indiquant si le paquet
  est une réponse ou une reqûete
*/
void process_smtp(const u_char*,int, int,int);

/*
  Affiche les informations FTP contenue dans
  le paquet, suivant le niveau de verbosité voulue
  La fonction demande également le nombre d'octet
  à afficher, et un booléen indiquant si le paquet
  est une réponse ou une reqûete
*/
void process_ftp(const u_char*,int, int,int);

#endif 