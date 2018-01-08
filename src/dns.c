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
    printf("Response\n");
  } else {
    printf("Request\n"); // 0
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
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohl(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += RSRLEN;
      printf("\t%*c  - Data: ",APP_SPACE,' ');
    //  if(ntohs(r->type) == 2){
    //    get_name(packet, following_info);
    //  } else if (ntohs(r->type)==1){
      int j;
      for(j=0; j<ntohs(r->length); j++){
        if(isprint(following_info[j]))
          printf("%c", following_info[j]);
      }   
    //  }
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
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohl(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += RSRLEN;
      int j;
      for(j=0; j<ntohs(r->length); j++){
        if(isprint(following_info[j]))
          printf("%c", following_info[j]);
      }
      printf("\t%*c --\n\n",APP_SPACE,' ');
      following_info += ntohs(r->length);
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
      printf("\t%*c  - Ttl: %d\n",APP_SPACE,' ', ntohl(r->ttl));
      printf("\t%*c  - Length: %d\n",APP_SPACE,' ', ntohs(r->length));
      following_info += RSRLEN;
      int j;
      for(j=0; j<ntohs(r->length); j++){
        if(isprint(following_info[j]))
          printf("%c", following_info[j]);
      }
      printf("\t%*c --\n\n",APP_SPACE,' ');
      following_info += ntohs(r->length);
    }
  }
}

int get_name(const u_char* packet,const u_char* sub ){
  int is_ptr;
  int length=0;
  while(sub[length] != 0){
    if(((u_int8_t)sub[length] & PTRMASK) == PTRVALUE){
      u_int16_t offset = sub[length] << 8;
      offset |= sub[length+1];
      offset &= PTRINDEXMASK;
      is_ptr = 1;
      get_name(packet, packet+offset);
      return 2;
    } else {
      if(isprint(sub[length+1]) && sub[length+1] != '\n')
        printf("%c",sub[length+1]);
      else
        printf(".");
      length++;
      is_ptr=0;
    }
  }
  if(!is_ptr) length++;
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