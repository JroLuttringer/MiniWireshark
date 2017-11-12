#include "../include/packet_processing.h"

void packet2hexa(const u_char* packet, const struct pcap_pkthdr* header) {
  unsigned int i = 0;
  for (i = 0; i < header->len; i++) {
    if (i % 16 == 0) printf("\n");
    printf(" %02x", packet[i]);
  }
  printf("\n\n");
}

int process_network_layer(const u_char* packet, uint32_t network_id) {
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
  return transport_layer;
}

int process_transport_layer(const u_char* packet, int transport_id) {
  switch (transport_id) {
    case UDP:
      break;
    case TCP:
      break;
    case ICMP:
      break;
    default:
      return 0;
  }
  return 0;
}

void got_packet(u_char* not_used, const struct pcap_pkthdr* header,
                const u_char* packet) {
  printf("\n=================== Received packet ======================== \n");
  // print packet in hexa
  packet2hexa(packet, header);

  // process ethernet and go to network layer
  uint32_t network_id = process_ethernet(packet);
  packet += sizeof(struct ether_header);

  // process network layer and go to transport layer
  int transport_id = process_network_layer(packet, network_id);
  if (transport_id == -1) return;

  // process transport layer
  process_transport_layer(packet, transport_id);

  printf("============================================================");
  printf("\n");
}