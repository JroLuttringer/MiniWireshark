#include "../include/my_ethernet.h"

void ethaddr2hexa(const uint8_t* addr) {
  int i;
  for (i = 0; i < ETH_ADDR_LEN; i++) {
    printf("%02x", addr[i]);
    if (i != 5) printf(":");
  }
  printf("\n");
}

char* ethernet_type(const struct ether_header* ethernet) {
  char* type;
  switch (ntohs(ethernet->ether_type)) {
    case ETHERTYPE_IP:
      type = " IP ";
      break;
    case ETHERTYPE_ARP:
      type = " ARP ";
      break;
    case ETHERTYPE_IPV6:
      type = " IPV6 ";
      break;
    case ETHERTYPE_REVARP:
      type = " REVERSE ARP ";
      break;
    default:
      type = "";
    }
  return type;
}

void process_ethernet(const u_char* packet, int* network_id) {
  struct ether_header* ethernet;
  ethernet = (struct ether_header*)(packet);
  printf("\n+ Ethernet :\n");
  printf("\t| Source        : ");
  ethaddr2hexa(ethernet->ether_shost);
  printf("\t| Destination   : ");
  ethaddr2hexa(ethernet->ether_dhost);
  printf("\t| Type : %s 0x%04x \n", ethernet_type(ethernet),
     ntohs(ethernet->ether_type)
    );
  printf("\t+___\n\n");
  *network_id = ethernet->ether_type;
}
