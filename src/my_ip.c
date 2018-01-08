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

int process_ip(const u_char* packet,int verbose) {
  const struct ip* ip;
  ip = (struct ip*)(packet);
  struct in_addr ip_src, ip_dst;
  ip_src = ip->ip_src;
  ip_dst = ip->ip_dst;

  if(verbose == 1){
    printf(" -IP : from %15s ",inet_ntoa(ip_src));
    printf("to %15s",inet_ntoa(ip_dst));
    return ip->ip_p;
  } 

  if(verbose ==2){
    printf("- IP Version %d, ",ip->ip_v);
    printf("Src: %s  , ",inet_ntoa(ip_src));
    printf("Dest: %s\n",inet_ntoa(ip_dst));
    return ip->ip_p;
  }
  printf("  + IP :\n");
  printf("    | Header Length : %d \n    | Version : %d \n    | ToS : 0x%02x \n    | Length : %d \n    | ID: %d",
  ip->ip_hl, ip->ip_v, ip->ip_tos, ntohs(ip->ip_len), ntohs(ip->ip_id));

  int reserved, dontfrag, morefrag, foffset;
  uint16_t flags = ntohs(ip->ip_off);
  reserved = (flags & IP_RF) ? 1 : 0;
  dontfrag = (flags & IP_DF) ? 1 : 0;
  morefrag = (flags & IP_MF) ? 1 : 0;
  foffset = flags & IP_OFFMASK;
  flags = flags >> 13;

  printf(
      "\n    | Flags : 0x%02x\n      - Reserved bit : %d\n      - Don't Fragment : %d\n      - More Fragments : %d\n    | Fragment Offset : %d\n    | ttl : %d \n    | Protocol : %s (%d) \n    | Checksum : %d\n",
      flags, reserved, dontfrag, morefrag, foffset, ip->ip_ttl, protocol_name(ip->ip_p),
      ip->ip_p, ip->ip_sum);


  printf("    | Source : %s\n", inet_ntoa(ip_src));
  printf("    | Dest : %s\n", inet_ntoa(ip_dst));
  printf("    +____\n");
  printf("\n");
  return ip->ip_p;
}
