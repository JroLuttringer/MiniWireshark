#include "../include/dhcp.h"


void print_dhcp_type(int type){
  printf(" %d  ",type);
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
    case DHCPNAK:
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

void print_dhcp_option(const u_char* packet,int indice,int verbose){
    if(verbose == 3)
      printf("%*c| Option: (%d) ",APP_SPACE,' ', packet[indice]);
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
      break;
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
      case TAG_VENDOR_CLASS:
        printf("Vendor Class");
        break;
      case TAG_OPT_OVERLOAD:
        printf("Opt Overload");
      break;
      case TAG_MAX_MSG_SIZE:
        printf("Maximum message size");
      break;
      default:
        printf("Not supported");
    }
}

void process_dhcp(const u_char* packet,int verbose){
  int i = 0;
  if(verbose != 3) printf("- DHCP : ");

  // VERBOSITE TROIS
  else printf("%*c- DHCP:\n",APP_SPACE_HDR,' ');
  
  // vendor spec = 60 + 4 (magic cookie)
  while(i<60){
    //print TLVs
    int length = packet[i+1];
    if(packet[i] == TAG_END){
      printf("%*cEnd\n",APP_SPACE,' ');
      break;
    }
    print_dhcp_option(packet, i, verbose);

    // Si la verbosité est < 3, on affiche uniquement le type du message
    if((packet[i] == TAG_DHCP_MESSAGE) && verbose != 3){
      return;
    }

    if(packet[i] == TAG_DHCP_MESSAGE && packet[i+1] == 1){
      i = i+3; // tout a déjà été lu dans les sous fonctions
    } else {
      i = i+2; // déjà lu T & L
      // afficher la valeur entre crochet
      printf(" [ ");
      while(length > 0){
        printf("%01x ", packet[i++]);
        length--;
      }
      printf(" ] ");
    }
    printf("\n");
  }
}

void process_bootp(const u_char* packet,int verbose){
  struct bootp* bootp_info = (struct bootp*) packet;
  int i ;

  /* Pour les verbosité < 3, on affiche uniquement les infos DHCP 
  Si DHCP est présent, et bootp sinon
  pour verbosité 3, on affiche les deux
  */
  if(verbose == 1){
    if(test_dhcp(bootp_info->bp_vend)){
      process_dhcp(bootp_info->bp_vend + 4,verbose);
    }
    else {
      printf("- BOOTP");
      printf(" (%d)",bootp_info->bp_op);
    }
    return;
  }

  if(verbose == 2){
    if(!test_dhcp(bootp_info->bp_vend)){
      printf("- Bootp: ");
      printf("Opcode: %d",bootp_info->bp_op);
      if(bootp_info->bp_op == BOOTREPLY) {
        printf("(Boot Reply)\n");
      } else {
        printf("(Boot Request)\n");
      }
    } else {
      process_dhcp(bootp_info->bp_vend + 4,verbose);
    }
    return;
  }

  // VERBOSE 3
  printf("%*c+ BOOTP: \n",APP_SPACE_HDR, ' ');
  printf("%*c| Opcode: %d",APP_SPACE,' ', bootp_info->bp_op);
  if(bootp_info->bp_op == BOOTREPLY){
    printf("(Boot Reply)\n");
  } else {
    printf("(Boot Request)\n");
  }
  if(bootp_info->bp_htype != 1){
    printf("%*c| Hardware Type: Unknown(%d)\n",APP_SPACE,' ', bootp_info->bp_htype);
  } else {
    printf("%*c| Hardware Type: Ethernet\n",APP_SPACE,' ');
  }
  printf("%*c| Hardwadre address length: %d\n",APP_SPACE,' ', bootp_info->bp_hlen);
  printf("%*c| Hops: %d\n",APP_SPACE,' ',bootp_info->bp_hops);
  printf("%*c| Transaction ID: 0x%08x\n",APP_SPACE,' ', ntohl(bootp_info->bp_xid));
  printf("%*c| Seconds elapsed: %d\n",APP_SPACE,' ', ntohs(bootp_info->bp_secs));
  printf("%*c| Bootp flags: 0x%04x  \n",APP_SPACE,' ',bootp_info->bp_flags);
  printf("%*c| Client IP Address: %s\n",APP_SPACE,' ',inet_ntoa(bootp_info->bp_ciaddr));
  printf("%*c| Your (client) IP Address: %s\n",APP_SPACE,' ',inet_ntoa(bootp_info->bp_yiaddr));
  printf("%*c| Next server IP Address: %s\n",APP_SPACE,' ',inet_ntoa(bootp_info->bp_siaddr));
  printf("%*c| Relay IP Address: %s\n",APP_SPACE,' ',inet_ntoa(bootp_info->bp_giaddr));
  printf("%*c| Client Mac Address: %s\n",APP_SPACE,' ',ether_ntoa((struct ether_addr*)&bootp_info->bp_chaddr));
  if(*bootp_info->bp_sname)
    printf("%*c| Server host name: %s\n",APP_SPACE,' ', bootp_info->bp_sname);
  else
    printf("%*c| Server host name not given\n",APP_SPACE,' ');

  if(*bootp_info->bp_file)
    printf("%*c| Boot file name: %s\n",APP_SPACE,' ', bootp_info->bp_file);
  else
    printf("%*c| Boot file name not given\n",APP_SPACE,' ');

  int dhcp = test_dhcp(bootp_info->bp_vend);
  printf("%*c| Vendor spec: ",APP_SPACE,' ');
  for(i=0; i<4; i++){
    printf("%02x", bootp_info->bp_vend[i]);
  }

  // Process DHCP si il y a du DHCP
  if(dhcp){
    printf(" (Magic cookie: DHCP)\n");
     printf("\n");
    process_dhcp(bootp_info->bp_vend + 4,verbose);
  } else {
    printf("\n");
  }
}


int test_dhcp(const u_char* cookie){
  int magic_cookie[4] = VM_RFC1048;
  int dhcp = 1;
  int i;
  for(i=0; i<4; i++){
    if(magic_cookie[i] != cookie[i]){
      dhcp = 0;
    }
  }
  return dhcp;
}


