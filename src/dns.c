#include "../include/dns.h"


void print_dns_opcode(int opcode){
  switch (opcode){
    case QUERY:
      printf("Query");
      break;
    case IQUERY:
      printf("Inverse Query");
      break;
    case SSR:
      printf("Server Status Request");
      break;
    case NOTIFY:
      printf("Notify");
      break;
    case UPDATE:
      printf("Update");
      break;
    default:
      printf("Not supported");

  }
  printf("(%d)\n", opcode);
}



void process_dns(const u_char* packet, int length){
  HEADER* dns_info = (HEADER*) packet;
  printf("DNS:\n");
  printf("\tID: %d\n", ntohs(dns_info->id));
  printf("\tType: ");
  if(dns_info->qr){
    printf("Response");
  } else {
    printf("Request"); // 0
  }
  printf("Opcode: ");
  print_dns_opcode(dns_info -> opcode);
  printf("Trucated: ");
  if(dns->tc){
    printf("The message is truncated\n");
  } else {
    printf("The message is not truncated\n");
  }
  printf("Recursion desired: ");
  if(dns->rd){
    printf("Do query recursively\n");
  } else {
    printf("Do not query recursively\n");
  }

  if(dns_info->qr){
    printf("Authoritative: ");

    printf("Recursion available: ");
  }




}
