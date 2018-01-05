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

  if(bootp->bp_file)
    printf("\tBoot File name: %s\n", bootp_info->bp_file;
  else
    printf("\tBoot File name unknown\n");

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



void process_dhcp(const u_char* packet){
    int i = 0;
    int option;
    printf("DHCP:\n");
    // vendor spec = 60 + 4 (magic cookie)
    while(i<60){
      //print Tlv
      int length = packet[i+1];
      if(packet[i] == TAG_END){
        printf(" End\n");
      }
      print_dhcp_option(packet, i);

      // TODO CHANGER
      if(pakcet[i] == TAG_DHCP_MESSAGE){
        i = i+3 // tout a déjà été lu dans les sous fonctions
      } else {
        i = i+2; // read T & L
        // read V
        while(length > 0){
          printf("%01x ", packet[i++]);
          length--;
        }
      }
      printf("\n");
    }

  }

  void print_dhcp_option(const u_char* packet,int indice){
      printf("\tOption: (%d) ", packet[indice]);
      switch(packet[indice]){
        case TAG_CLIENT_ID:
          printf("Client identifier");
        break;
        case TAG_SUBNET_MASK:
          printf("Subnet mask");
        break;
        case TAG_SERVER_ID:
          printf("Server ID");
        break;
        case TAG_IP_LEASE:
          printf("Ip lease time");
        break;
        case TAG_REBIND_TIME:
          printf("Rebind time");
        break;
        case TAG_REQUESTED_IP:
          printf("Requested IP:");
        case TAG_PARM_REQUEST:
          printf("Parameters request list");
        break;
        case TAG_RENEWAL_TIME:
          printf("Renewal time");
        break;
        case TAG_DHCP_MESSAGE:
          printf("DHCP Message type ");
          print_dhcp_type(packet[indice+2]);
        break;
        default:
          printf("Not supported");
      }
      printf("\n");
  }

  void print_dhcp_type(int type){
    printf("Type: (%d) ",type);
    switch(type){
      case DHCPDISCOVER:
        printf("(DISCOVER)");
        break;
      case DHCPOFFER:
        printf("(OFFER)");
      break;
      case DHCPREQUEST:
        printf("(REQUEST)");
      break;
      case DHCPDECLINE:
        printf("(DECLINE)");
      break;
      case DHCPACK:
        printf("(ACK)");
      break;
      case DHCPNACK:
        printf("(NACK)");
      break;
      case DHCPRELEASE:
        printf("(RELEASE)");
      break;
      case DHCPINFORM:
        printf("(INFORM)");
      break;


    }
  }
