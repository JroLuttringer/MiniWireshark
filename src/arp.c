#include "../include/arp.h"


void process_arp(const u_char* packet){
    struct arphdr* arp_info = (struct arphdr*) packet;
    printf("+ ARP :\n");
    printf("\t| Hardware Type: ");
    switch(ntohs(arp_info->ar_hrd)){
        case ARPHRD_ETHER:
            printf("Ethernet\n");
            break;
        case ARPHRD_EETHER:
            printf("Experimental Ethernet\n");
            break;
        case ARPHRD_APPLETLK:
            printf("Apple Talk\n");
            break;
        default:
            printf("Unknown\n");
    }
    printf("\t| Protocol type: ");
    switch(ntohs(arp_info->ar_pro)){
        case ETHERTYPE_IP:
            printf("IP\n");
            break;
        case ETHERTYPE_PUP:
            printf("PUP\n");
            break;
        default:
            printf("Unkown\n");
    }
    printf("\t| Hardware size: %d\n",arp_info->ar_hln);
    printf("\t| Protocol: %d\n",arp_info->ar_pln);
    printf("\t| Opcode: ");
    switch(ntohs(arp_info->ar_op)){
        case ARPOP_REQUEST:
            printf("ARP request operation\n");
            break;
        case ARPOP_REPLY:
            printf("ARP reply operation\n");
            break;
        case ARPOP_RREQUEST:
            printf("RARP request operation\n");
            break;
        case ARPOP_RREPLY:
            printf("RARP request operation\n");
            break;
        case ARPOP_InREQUEST:
            printf("InARP request \n");
            break;
        case ARPOP_InREPLY:
            printf("InARP reply\n");
            break;
        default:
            printf("Unkown\n");
    }
    if( (ntohs(arp_info->ar_hrd)==ARPHRD_ETHER) && (ntohs(arp_info->ar_pro) == ETHERTYPE_IP)) {
        struct ether_arp* test = (struct ether_arp*) arp_info;
       /* char* dest_mac_addr = ether_ntoa((struct ether_addr*)&test->arp_tha);  
        char* sdr_mac_addr  = ether_ntoa((struct ether_addr*)&test->arp_sha);    
        char* dest_ip_addr  = inet_ntoa(*(struct in_addr*)&test->arp_tpa) ;
        char* sdr_ip_addr   =inet_ntoa(*(struct in_addr*)&test->arp_spa);*/

        printf("\t| Sender MAC address: %s\n", ether_ntoa((struct ether_addr*)&test->arp_sha));
        printf("\t| Sender IP address: %s\n", inet_ntoa(*(struct in_addr*)&test->arp_spa));
        printf("\t| Destination MAC address: %s\n",ether_ntoa((struct ether_addr*)&test->arp_tha) );
        printf("\t| Destination IP address: %s\n", inet_ntoa(*(struct in_addr*)&test->arp_tpa));
        printf("\t+___");

    } 
    packet +=  sizeof(struct arphdr);
    print_data(packet);   
        

}
