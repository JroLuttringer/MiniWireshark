#include "../include/packet_processing.h"


int find_application(const u_char* packet, int port, int length, int is_source,int verbose){
  switch(port){
    case IMAP:
      process_imap(packet, length, is_source, verbose);
      break;
    case HTTP:
      process_http(packet, length, is_source, verbose);
      break;
    case POP:
      process_pop(packet, length, is_source, verbose);
      break;
    case SMTP:
    case SMTPS:
      process_smtp(packet, length, is_source, verbose);
      break;
    case FTPC:
    case FTPD:
      process_ftp(packet, length, is_source, verbose);
      break;
    case TELNET:
      process_telnet(packet, length, verbose);
      break;
    case DHCP:
      process_bootp(packet, verbose);
      break;
    case DNS:
      process_dns(packet, verbose);
      break;
    default:
      return 0;
  }
  return 1;
}

void process_app(const u_char* packet, int port_src, int port_dest, int length,int verbose){
  if( !find_application(packet,port_src, length, 1, verbose) && !find_application(packet,port_dest, length, 0, verbose)){
    printf(" Application not found.\n");
  }
}

void process_network_layer(const u_char* packet, uint32_t network_id,int* transport_id,int verbose) {
  int transport_layer = -1;
  switch (ntohs(network_id)) {
    case ETHERTYPE_IP:
      transport_layer = process_ip(packet,verbose);
      break;
    case ETHERTYPE_ARP:
      process_arp(packet,verbose);
      break;
    break;
    default:
      printf("Not supported\n");
  }
  *transport_id = transport_layer;
}

int process_transport_layer(const u_char* packet, int transport_id, int* port_src, int* port_dst, int* length,int verbose) {
  switch (transport_id) {
    case UDP:
      process_udp(packet, port_src, port_dst, length,verbose);
      break;
    case TCP:
      process_tcp(packet, port_src, port_dst, length,verbose);
      break;
    default:
      return 0;
  }
  return 0;
}

