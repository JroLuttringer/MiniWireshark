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
  printf("IP :\n");
  printf(
      "\tHeader Length : %d \n\tVersion : %d \n\tToS : 0x%02x \n\tLength : %d \n\tID "
      ": %d",
      ip->ip_hl, ip->ip_v, ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id));

  int reserved, dontfrag, morefrag, foffset;
  uint16_t flags = ntohs(ip->ip_off);
  reserved = (flags & IP_RF) ? 1 : 0;
  dontfrag = (flags & IP_DF) ? 1 : 0;
  morefrag = (flags & IP_MF) ? 1 : 0;
  foffset = flags & IP_OFFMASK;
  flags = flags >> 13;

  printf(
      "\n\tFlags : 0x%02x\n\t\t Reserved bit : %d\n\t\t Don't Fragment : "
      "%d\n\t\t More Fragments : %d\n\tFragment Offset : %d\n\tttl : %d "
      "\n\tProtocol : %s (%d) \n\tChecksum : "
      "%d\n",
      flags, reserved, dontfrag, morefrag, foffset, ip->ip_ttl, protocol_name(ip->ip_p),
      ip->ip_p, ip->ip_sum);

  struct in_addr ip_src, ip_dst;
  ip_src = ip->ip_src;
  ip_dst = ip->ip_dst;
  printf("\tSource : %s\n", inet_ntoa(ip_src));
  printf("\tDest : %s\n", inet_ntoa(ip_dst));
  return ip->ip_p;
}
