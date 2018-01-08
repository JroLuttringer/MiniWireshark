#include "../include/utils.h"

void packet_to_hexa(const u_char* packet, const struct pcap_pkthdr* header) {
  unsigned int i = 0;
  for (i = 0; i < header->len; i++) {
    if (i % 26 == 0) printf("\n");
    printf(" %02x", packet[i]);
  }
  printf("\n\n");
  for (i = 0; i < header->len; i++) {
    if (i % 20 == 0) printf("\n");
    if(isprint(packet[i]))
      printf(" %c", packet[i]);
    else
      printf(" .");
  }
  printf("\n\n");
}

void print_ascii(const u_char* packet, int length) {
  int i = 0;
  int print_tab = 1;
  for (i = 0; i < length; i++) {
      if(print_tab){
          printf("        ");
          print_tab=0;
      }
      if(packet[i]=='\r') printf("\\r");
      else if(packet[i]=='\n'){ printf("\\n"); printf("\n");}
      else if((isprint(packet[i]) || isspace(packet[i])))printf("%c", packet[i]);
      if(packet[i]=='\n') print_tab=1;
  }
  printf("\n\n");
}


void print_data(const u_char* packet) {
  unsigned int i = 0;
  printf("\t Data: ");
  for (i = 0; i < 50; i++) {
    if(packet[i])
      printf("%02x", packet[i]);
    else break;
  }
  printf(" ...\n");
}
