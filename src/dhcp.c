#include "../include/dhcp.h"
#include "../include/bootp.h"



void process_bootp(const u_char* packet, int length){
  struct bootp* bootp_info = (struct bootp*) packet;
  printf("BOOTP: \n");
  printf("\tOpcode: %d", bootp_info->bp_op);
  if(bootp_info->bp_op == BOOTREPLY){
    printf("(boot reply)\n");
  } else {
    printf("(boot Request)\n");
  }
  if(bootp_info->bp_htype != 1){
    printf("\tHardware Type: Unknown(%s)\n", bootp_info->bp_htype);
  } else {
    printf("\tHardware Type: Ethernet\n");
  }
  printf("\tHardwadre address length: %d\n", bootp_info->bp_hlen);
  printf("\tHops: %d_n",bootp_info->bp_hops);
  printf("\tTransaction ID: 0x%08x\n", ntohl(bootp_info->bp_xid));
  printf("\tSeconds since boot: %d\n", ntohs(bootp_info->bp_secs));
  printf("\tFlags: 0x%04x  \n",bootp_info->bp_flags);
  printf("\tClient IP Address: %s\n",inet_ntoa(bootp_info->bp_ciaddr));
  printf("\tYour IP Address: %s\n",inet_ntoa(bootp_info->bp_yiaddr));
  printf("\tServer IP Address: %s\n",inet_ntoa(bootp_info->bp_siaddr));
  printf("\tGateway IP Address: %s\n",inet_ntoa(bootp_info->bp_giaddr);
  printf("\tClient Mac Address: %s\n",ether_ntoa((struct ether_addr*)&bootp->bp_chaddr));
  if(bootp_info->bp_sname)
    printf("\tServer Host Name: %s\n", bootp_info->bp_sname);
  else
    printf("\tServer Host Name Unknown\n");
  printf("\tBoot File name: %s\n", bootp_info->bp_file;

  int magic_cookie[4] = VM_RFC1048;
  int dhcp = 1;
  int i ;
  printf("\tVendor spec: ");
  for(i=0; i<4; i++){
    if(magic_cookie[i] != bootp_info->bp_vend[i]){
      printf("%02x", bp_vend[i]);
      dhcp = 0;
    }
  }

  if(dhcp){
    printf("(DHCP)");
    process_dhcp(bootp_info->bp_vend + 4);
  }



  process_dhcp(const u_char* packet){
    int i = 0;
    int option;
    printf("DHPC:\n");
    // vendor spec = 60 + 4 (magic cookie)
    for(i=0; i < 60; i++){
      //print Tlv
      int length = packet[i+1];
      if(packet[i] == TAG_END){
        printf(" End\n");
      }
      print_dhcp_option(packet[i]);
      i = i+2; // read T & L
      // read V
      while(length > 0){
        printf("%01x ", packet[i++]);
        length--;
      }
      i-- ;
      printf("\n");
    }

  }
