#include "../include/dns.h"


void print_dns_opcode(int opcode){
  switch (opcode){
    case DNSQUERY:
      printf("Query");
      break;
    case DNSIQUERY:
      printf("Inverse Query");
      break;
    case DNSSSR:
      printf("Server Status Request");
      break;
    case DNSNOTIFY:
      printf("Notify");
      break;
    case DNSUPDATE:
      printf("Update");
      break;
    default:
      printf("Not supported");

  }
  printf("(%d)\n", opcode);
}



void process_dns( const u_char* packet){
  int i;
  HEADER* dns_info = (HEADER*) packet;
  printf("%*c+ DNS:\n",APP_SPACE,' ');
  printf("\t%*c| ID: %d\n",APP_SPACE,' ' ,ntohs(dns_info->id));
  printf("\t%*c| Type: ",APP_SPACE,' ');
  if(dns_info->qr){
    printf("Response");
  } else {
    printf("Request"); // 0
  }
  printf("\t%*c| Flags: ",APP_SPACE,' ');
  print_dns_opcode(dns_info -> opcode);
  printf("\t%*c| Trucated: ",APP_SPACE,' ');
  if(dns_info->tc){
    printf("The message is truncated\n");
  } else {
    printf("The message is not truncated\n");
  }
  printf("\t%*c| Recursion desired: ",APP_SPACE,' ');
  if(dns_info->rd){
    printf("Do query recursively\n");
  } else {
    printf("Do not query recursively\n");
  }
  printf("\t%*c| Recursion authorized: ",APP_SPACE,' ');
  if(dns_info->ra){
    printf("yes\n");
  } else {
    printf("no\n");
  }
  display_rcode(dns_info->rcode);
  printf("\t%*c| Questions: %d\n",APP_SPACE, ' ', ntohs(dns_info->qdcount));
  printf("\t%*c| Answer RRs: %d\n",APP_SPACE, ' ', ntohs(dns_info->ancount));
  printf("\t%*c| Authority RRs: %d\n",APP_SPACE, ' ', ntohs(dns_info->nscount));
  printf("\t%*c| Additional RRs: %d\n",APP_SPACE, ' ', ntohs(dns_info->arcount));
  const u_char* following_info = packet + 12;//sizeof(HEADER);

  if(ntohs(dns_info->qdcount)){
    printf("\t%*c| Questions: \n",APP_SPACE,' ');
    for(i=0; i<ntohs(dns_info->qdcount); i++){
      printf("\t%*c --\n",APP_SPACE,' ');
      printf("\t%*c  - Name: ",APP_SPACE,' ');
      following_info = following_info + get_name(packet, following_info);
      struct qst* q = (struct qst*) following_info;
      printf("\n");
      printf("\t%*c  - Type: %d\n",APP_SPACE,' ', ntohs(q->type));
      printf("\t%*c  - Class: %d\n",APP_SPACE,' ', ntohs(q->clss));
      following_info += QSTLEN;    
      printf("\t%*c --\n\n",APP_SPACE,' '); 
    }
  }
  if(ntohs(dns_info->ancount)){
    printf("\t%*c| Answers: \n",APP_SPACE,' ');
    for(i=0; i<ntohs(dns_info->ancount); i++){
      printf("\t%*c --\n",APP_SPACE,' ');
      printf("\t%*c  - Name: ",APP_SPACE,' '); 
      following_info = following_info + get_name(packet,following_info);
      printf("%*c\n",APP_SPACE,' ');
      struct resource* r = (struct resource*) following_info;
      printf("\t%*c  - Type: %d\n",APP_SPACE,' ', ntohs(r->type));
      printf("\t%*c  - Class: %d\n",APP_SPACE,' ', ntohs(r->clss));
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohs(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += RSRLEN;
      printf("\t%*c  - Data: ",APP_SPACE,' ');
      if(ntohs(r->type) == 2){
        get_name(packet, following_info);
      } else if (ntohs(r->type)==1){
        int j;
        for(j=0; j<ntohs(r->length); j++){
          printf("%c", following_info[j]);
        }
        
      }
      printf("\n");
      printf("\t%*c --\n\n",APP_SPACE,' ');
      following_info += ntohs(r->length);
    }
  }

  if(ntohs(dns_info->nscount)){
    for(i=0; i<ntohs(dns_info->nscount);i++){
      printf("\t%*c| Authority:\n",APP_SPACE,' ');
      printf("\t%*c --\n",APP_SPACE,' ');
      printf("\t%*c  - Name:\n",APP_SPACE,' ');
      following_info += get_name(packet, following_info);
      printf("\n");
      struct resource* r = (struct resource*) following_info;
      printf("\t%*c  - Type: %d\n",APP_SPACE,' ', ntohs(r->type));
      printf("\t%*c  - Class: %d\n",APP_SPACE,' ', ntohs(r->clss));
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohs(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += ntohs(r->length);
      printf("\t%*c --\n\n",APP_SPACE,' ');
    }
  }

  if(ntohs(dns_info->arcount)){
    printf("\t%*c| Additionals:\n",APP_SPACE,' ');
    for(i=0; i<ntohs(dns_info->arcount);i++){
      printf("\t%*c --\n",APP_SPACE,' ');
      printf("\t%*c  - Name:\n",APP_SPACE,' ');
      following_info+=get_name(packet, following_info);
      printf("\n");
      struct resource* r = (struct resource*) following_info;
      printf("\t%*c  - Type: %d\n",APP_SPACE,' ', ntohs(r->type));
      printf("\t%*c  - Class: %d\n",APP_SPACE,' ', ntohs(r->clss));
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohs(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += ntohs(r->length);
      printf("\t%*c --\n\n",APP_SPACE,' ');
    }
  }
}

int get_name(const u_char* packet,const u_char* sub ){
  int i;
  int length=2;
  //check if pointer
  if(((u_int8_t)sub[0] & PTRMASK) == PTRVALUE){

    u_int16_t offset = sub[0] << 8;
    offset |= sub[1];
    offset &= PTRINDEXMASK;
    get_name(packet, packet+offset);
    length=2;
  } else { // if name
    // print name
    i=1;
    while(sub[i] != 0) {
      if(isprint(sub[i]))
        printf("%c",sub[i]);
      else
        printf(".");
      i++;
      length++;
    }
  }
  return length;
}

void display_rcode(int rcode){
  printf("\t%*c| Rcode: ",APP_SPACE,' ');
  switch (rcode){
    case DNSNOERROR :
        printf("No error");
        break;
    case DNSFORMERR :
        printf("Format Error");
        break;
    case DNSSERVFAIL :
        printf("Server Failure");
        break;
    case DNSNXDOMAIN :
        printf("Non Existent Domain");
        break;
    case DNSNOTIMP :
        printf("Not implemented");
        break;
    case DNSREFUSED :
        printf("Query Refused");
        break;
    case DNSYXDOMAIN :
        printf("Name Exists when it should not");
        break;
    case DNSYXRRSET :
        printf("RR set Exists when it should not");
        break;
    case DNSBADCOOKIE :
        printf("Bad/missing Server Cookie");
        break;
    default:
      printf("Unknown");
  }
  printf(" (%d)\n", rcode);  
}