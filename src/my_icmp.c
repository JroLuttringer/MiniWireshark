#include "../include/my_icmp.h"

void process_icmp(const u_char* packet){
    struct icmphdr* icmp_info = (struct icmphdr*) packet;
    printf("+ ICMP : \n");
    printf("\t| Type : ");
    switch(icmp_info->type){
        case ICMP_ECHO:
            printf(" Echo Request\n");
        break;
        case ICMP_ECHOREPLY:
            printf(" Echo Reply\n");
            break;
        case ICMP_REDIRECT:
            printf(" Redirect\n");
            break;
        case ICMP_DEST_UNREACH:
            printf(" Destination Unreachable\n");
            break;
        case ICMP_SOURCE_QUENCH:
            printf(" Source Quench\n");
            break;
        case ICMP_TIME_EXCEEDED:
            printf(" Time Exceeded\n");
            break;
        case ICMP_PARAMETERPROB:
            printf(" Parameter Problem\n");
            break;
        case ICMP_TIMESTAMP:
            printf("Timestamp Request\n");
            break;
        case ICMP_TIMESTAMPREPLY:
            printf("Timestamp Reply\n");
            break;
        case ICMP_INFO_REQUEST:
            printf("Info Request\n");
        break;
        case ICMP_INFO_REPLY:
            printf("Info reply\n");
        break;
        case ICMP_ADDRESS:
            printf("Address Mask Requestion\n");
        break;
        case ICMP_ADDRESSREPLY:
            printf("Address Mask Reply\n");
        break;
        default:
            printf("Unknown ICMP Type\n");
        
        }
    if(icmp_info -> type == ICMP_DEST_UNREACH || icmp_info->type == ICMP_REDIRECT || icmp_info->type == ICMP_TIME_EXCEEDED){
        switch(icmp_info->code){
            case ICMP_NET_UNREACH:
            printf("Network Unreachable\n");
            break;
            case ICMP_HOST_UNREACH:
            printf("Host Unreachable\n");
            break;
            case ICMP_PROT_UNREACH:
            printf("Protocol Unreachable\n");
            break;
            case ICMP_PORT_UNREACH:
            printf("Port Unreachable\n");
            break;
            case ICMP_FRAG_NEEDED:
            printf("Fragmentation Needed\n");
            break;
            case ICMP_SR_FAILED:
            printf("Source Route Failed\n");
            break;
            case ICMP_NET_UNKNOWN:
            printf("Network Unknown\n");
            break;
            case ICMP_HOST_UNKNOWN:
            printf("Host Unknown\n");
            break;
            case ICMP_HOST_ISOLATED:
            printf("Host Isolated\n");
            break;
            case ICMP_NET_ANO:
            printf("Network Ano\n");
            break;
            case ICMP_HOST_ANO:
            printf("Host Ano\n");
            break;
            case ICMP_NET_UNR_TOS:
            printf("Network UNR ToS\n");
            break;
            case ICMP_HOST_UNR_TOS:
            printf("Host Unr ToS\n");
            break;
            case ICMP_PKT_FILTERED:
            printf("Packet Filtered\n");
            break;
            case ICMP_PREC_VIOLATION:
            printf("Precedence Violation\n");
            break;
            case ICMP_PREC_CUTOFF:
            printf("Precedence Cut Off\n");
            break;
            default:
            printf("Unknown Code\n");
        }
    }
    printf("\t| Checksum: %d\n", ntohs(icmp_info->checksum));
    printf("\t| Id : %d\n", ntohs(icmp_info->un.echo.id));
    printf("\t| Sequence : %d\n", ntohs(icmp_info->un.echo.sequence));

    
}