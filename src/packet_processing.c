#include "../include/packet_processing.h"

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
          printf("\t");
          print_tab=0;
      }
      if(packet[i]=='\r') printf("\\r");
      else if(packet[i]=='\n'){ printf("\\n"); printf("\n");}
      else if((isprint(packet[i]) || isspace(packet[i])))printf("%c", packet[i]);
      if(packet[i]=='\n' && packet[i-1]=='\r') print_tab=1;
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

int find_application(const u_char* packet, int port, int length, int is_source){
  switch(port){
    case IMAP:
      process_imap(packet, length, is_source);
      break;
    case HTTP:
      process_http(packet, length, is_source);
      break;
    case POP:
      process_pop(packet, length, is_source);
      break;
    case SMTP:
    case SMTPS:
      process_smtp(packet, length, is_source);
      break;
    case FTPC:
    case FTPD:
      process_ftp(packet, length, is_source);
      break;
    case TELNET:
      process_telnet(packet, length);
      break;
    case DHCP:
      process_bootp(packet);
      break;
    case DNS:
      process_dns(packet);
      break;
    default:
      return 0;
  }
  return 1;
}

void process_app(const u_char* packet, int port_src, int port_dest, int length){
  if( !find_application(packet,port_src, length, 1) && !find_application(packet,port_dest, length, 0)){
    printf(" Application not found.\n");
  }
}

void process_network_layer(const u_char* packet, uint32_t network_id,int* transport_id) {
  int transport_layer = -1;
  switch (ntohs(network_id)) {
    case ETHERTYPE_IP:
      transport_layer = process_ip(packet);
      break;
    case ETHERTYPE_ARP:
      process_arp(packet);
      break;
    break;
    default:
      printf("Not supported\n");
  }
  *transport_id = transport_layer;
}

int process_transport_layer(const u_char* packet, int transport_id, int* port_src, int* port_dst, int* length) {
  switch (transport_id) {
    case UDP:
      process_udp(packet, port_src, port_dst, length);
      break;
    case TCP:
      process_tcp(packet, port_src, port_dst, length);
      break;
    default:
      return 0;
  }
  return 0;
}

void got_packet(u_char* not_used, const struct pcap_pkthdr* header,
                const u_char* packet) {
  int network_id   = 0;
  int transport_id = 0;
  int port_dst = 0;
  int port_src = 0;
  int length = 0;
  int total_length = 0;
  static int nb_pqt = 1;

  printf("\n======== Received packet #%d ============================================================ \n",nb_pqt++);
  // print packet in hexa
  packet_to_hexa(packet, header);
  // process ethernet and set pointer to network layer
  process_ethernet(packet, &network_id);
  packet += sizeof(struct ether_header);
  total_length += sizeof(struct ether_header);

  // process network layer and set pointer to transport layer
  process_network_layer(packet, network_id, &transport_id);

  // Process transport layer or ICMP
  if(ntohs(network_id) == ETHERTYPE_IP){
    packet += sizeof(struct ip);
    total_length += sizeof(struct ip);
    if(transport_id == ICMP){
      process_icmp(packet);
      packet += sizeof(struct icmphdr)+8;
      print_data(packet);

    } else {
      process_transport_layer(packet, transport_id, &port_src, &port_dst, &length);
      packet += length;
      total_length += length;
      process_app(packet, port_src, port_dst, header->len - total_length);

    }
  }

  // process transport layer
  printf("===================================================================================================");
  printf("\n");
}
