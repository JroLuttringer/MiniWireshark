#include "../include/packet_processing.h"

void packet_to_hexa(const u_char* packet, const struct pcap_pkthdr* header) {
  unsigned int i = 0;
  for (i = 0; i < header->len; i++) {
    if (i % 26 == 0) printf("\n");
    printf(" %02x", packet[i]);
  }
  printf("\n\n");
  for (i = 0; i < header->len; i++) {
    if (i % 16 == 0) printf("\n");
    if(isprint(packet[i]))
      printf(" %c", packet[i]);
    else
      printf(" .");
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

int find_application(int port){
  switch(port){
    case DHCP:
      //process_dhcp(packet);
      break;
    case HTTP:
     // process_http(packet);
      break;
    default:
      return 0;
  }
  return 1;  
}

void process_app(const u_char* packet, int port_src, int port_dest){
  if( !find_application(port_src) && !find_application(port_dest)){
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

  printf("\n=================== Received packet ============================================================ \n");
  // print packet in hexa
  packet_to_hexa(packet, header);
  // process ethernet and set pointer to network layer
  process_ethernet(packet, &network_id);
  packet += sizeof(struct ether_header);

  // process network layer and set pointer to transport layer
  process_network_layer(packet, network_id, &transport_id);
            
  // Process transport layer or ICMP
  if(ntohs(network_id) == ETHERTYPE_IP){
    packet += sizeof(struct ip);
    if(transport_id == ICMP){
      process_icmp(packet);
      packet += sizeof(struct icmphdr)+8;
      print_data(packet);
    } else {
      process_transport_layer(packet, transport_id,&port_src, &port_dst, &length);
      packet += length;
      process_app(packet,port_src, port_dst);
    }
  } 

  // process transport layer
  printf("===================================================================================================");
  printf("\n");
}