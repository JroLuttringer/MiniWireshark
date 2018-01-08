#include "../include/my_ethernet.h"

void ethaddr2hexa(const uint8_t* addr) {
  int i;
  for (i = 0; i < ETH_ADDR_LEN; i++) {
    printf("%02x", addr[i]);
    if (i != 5) printf(":");
  }

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

void process_ethernet(const u_char* packet, int* network_id,int verbose) {
  struct ether_header* ethernet;
  ethernet = (struct ether_header*)(packet);
  *network_id = ethernet->ether_type;
  if(verbose == 1) return;
  if(verbose == 2){
    printf("- Ethernet, ");ethaddr2hexa(ethernet->ether_shost);printf(" to ");ethaddr2hexa(ethernet->ether_dhost);
    printf("\n");
    return;
  }
  ethernet = (struct ether_header*)(packet);
  printf("\n+ Ethernet :\n");
  printf("  | Source        : ");
  ethaddr2hexa(ethernet->ether_shost);
  printf("\n");
  printf("  | Destination   : ");
  ethaddr2hexa(ethernet->ether_dhost);
  printf("\n");
  printf("  | Type : %s 0x%04x \n", ethernet_type(ethernet),
     ntohs(ethernet->ether_type)
    );
  printf("  +___\n\n");
}
