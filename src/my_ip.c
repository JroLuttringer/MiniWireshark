#include "../include/my_ip.h"

char* protocol_name(int id) {
  char* name;
  switch (id) {
    case 6:
      name = "TCP";
      break;
    case 17:
      name = "UDP";
      break;
    case 1:
      name = "ICMP";
      break;
    default:
      name = "Unknown";
      break;
  }
  return name;
}

int process_ip(const u_char* packet) {
  const struct ip* ip;
  ip = (struct ip*)(packet);
  printf("  + IP :\n");
  printf("\t  | Header Length : %d \n\t  | Version : %d \n\t  | ToS : 0x%02x \n\t  | Length : %d \n\t  | ID: %d",
  ip->ip_hl, ip->ip_v, ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id));

  int reserved, dontfrag, morefrag, foffset;
  uint16_t flags = ntohs(ip->ip_off);
  reserved = (flags & IP_RF) ? 1 : 0;
  dontfrag = (flags & IP_DF) ? 1 : 0;
  morefrag = (flags & IP_MF) ? 1 : 0;
  foffset = flags & IP_OFFMASK;
  flags = flags >> 13;

  printf(
      "\n\t  | Flags : 0x%02x\n\t    - Reserved bit : %d\n\t    - Don't Fragment : %d\n\t    - More Fragments : %d\n\t  | Fragment Offset : %d\n\t  | ttl : %d \n\t  | Protocol : %s (%d) \n\t  | Checksum : %d\n",
      flags, reserved, dontfrag, morefrag, foffset, ip->ip_ttl, protocol_name(ip->ip_p),
      ip->ip_p, ip->ip_sum);

  struct in_addr ip_src, ip_dst;
  ip_src = ip->ip_src;
  ip_dst = ip->ip_dst;
  printf("\t  | Source : %s\n", inet_ntoa(ip_src));
  printf("\t  | Dest : %s\n", inet_ntoa(ip_dst));
  printf("\t  +____\n");
  printf("\n");
  return ip->ip_p;
}
