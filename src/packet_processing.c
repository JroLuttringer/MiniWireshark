#include "../include/packet_processing.h"

void packet_to_hexa(const u_char* packet, const struct pcap_pkthdr* header) {
  unsigned int i = 0;
  for (i = 0; i < header->len; i++) {
    if (i % 16 == 0) printf("\n");
    printf(" %02x", packet[i]);
  }
  printf("\n\n");
}

void process_network_layer(const u_char* packet, uint32_t network_id,int* transport_id) {
  int transport_layer = -1;
  switch (ntohs(network_id)) {
    case ETHERTYPE_IP:
      transport_layer = process_ip(packet);
      break;
    case ETHERTYPE_ARP:
      break;
    case ETHERTYPE_REVARP:
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

  printf("\n=================== Received packet ======================== \n");
  // print packet in hexa
  packet_to_hexa(packet, header);
  // process ethernet and set pointer to network layer
  process_ethernet(packet, &network_id);
  packet += sizeof(struct ether_header);
  // process network layer and set pointer to transport layer
  process_network_layer(packet, network_id, &transport_id);
  // process transport layer
  if(transport_id == ICMP){
    process_icmp(packet);
  } else {
    process_transport_layer(packet, transport_id,&port_src, &port_dst, &length);
  }
  printf("============================================================");
  printf("\n");
}