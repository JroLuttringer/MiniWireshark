#ifndef __TELNET_H_
#define __TELNET_H_

#include <stdio.h>
#include <stdlib.h>
#include "../include/utils.h"

#define WILL 251
#define WONT 252
#define DO 253
#define DONT 254
#define IAC 255
#define SE 240 //subnegoc end
#define NOP 241
#define DM 242 // data mark
#define BRK 243 //break
#define IP 244 // interrupt
#define AO 245 // Abort output
#define AYT 246 // Are you there
#define EC 247 // Erase char
#define EL 248 // Erase line
#define GA 249 // go ahead
#define SB 250 // subnegoc

#define ECHO 1
#define RECONNECT 2
#define SUPP_GO_AHEAD 3
#define STATUS 5
#define TIM_MARK 6
#define LINE_WIDTH 8
#define TERM_TYPE 24
#define WIN_SIZE 31
#define TERM_SPEED 32
#define REM_FLOW_CTRL 33
#define LINEMODE 34
#define ENV_VAR 36

/* Affiche en texte la commande telnet passée en argument */
void display_command(int);

/* Affiche en texte l'option telnet passée en argument */
void display_option(int);

/* Affiche les information Telnet 
  contenu dans la couche application, suivant le niveau de verbosité
  et le nombre d'octet à afficher
*/
void process_telnet(const u_char*, int,int );


#endif
