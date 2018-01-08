#include "../include/udp_tcp.h"

void process_udp(const u_char* packet, int* port_src, int* port_dst, int* length, int verbose){
    struct udphdr* udp_info = (struct udphdr*) packet;
    *port_src = ntohs(udp_info->uh_sport);
    *port_dst = ntohs(udp_info->uh_dport);
    int cksum = ntohs(udp_info->uh_sum);
    int length_data = ntohs(udp_info->uh_ulen);
    *length = sizeof(struct udphdr);

    if(verbose == 1){
        printf(" - UDP ");
        return;
    }
    if(verbose == 2){
        printf("- UDP, Src Port: %d, Dst Port: %d\n",ntohs(udp_info->uh_sport), ntohs(udp_info->uh_dport));
        return;
    }
    

    printf("%*c+ UDP :\n",TSP_SPACE_HDR,' ');
    printf("%*c| Source Port : %d\n",TSP_SPACE,' ', *port_src);
    printf("%*c| Destination Port : %d\n",TSP_SPACE,' ', *port_dst);
    printf("%*c| Checksum : %d\n",TSP_SPACE,' ', cksum);
    printf("%*c| Length: %d\n",TSP_SPACE,' ',length_data);
    printf("%*c+_____\n",TSP_SPACE,' ');
    printf("\n");
    
}


void process_tcp(const u_char* packet, int* port_src, int* port_dst, int* length, int verbose){
    struct tcphdr* tcp_info = (struct tcphdr*) packet;
    *port_src = ntohs(tcp_info->th_sport);
    *port_dst = ntohs(tcp_info->th_dport);
    int fin = (tcp_info->th_flags & TH_FIN) ? 1 : 0;
    int syn = (tcp_info->th_flags & TH_SYN) ? 1 : 0;
    int rst = (tcp_info->th_flags & TH_RST) ? 1 : 0;
    int push= (tcp_info->th_flags & TH_PUSH) ? 1 : 0;
    int ack = (tcp_info->th_flags & TH_ACK) ? 1 : 0;
    int urg = (tcp_info->th_flags & TH_URG) ? 1 : 0;
    int window = ntohs(tcp_info->th_win);
    int cksum = ntohs(tcp_info->th_sum);
    *length = tcp_info->th_off * 4;
    int seq = ntohs(tcp_info->th_seq);
    int ack_seq = ntohs(tcp_info->ack_seq);
    int data_offset = tcp_info->th_off;
    int urg_pointer = ntohs(tcp_info->th_urp);

    if(verbose == 1){
        printf(" - TCP ");
        printf(" [ ");
        if(fin)  printf("FIN ");
        if(syn)   printf("SYN ");
        if(rst) printf("RST ");
        if(push) printf("PSH ");
        if(ack) printf("ACK ");
        if(urg) printf("URG ");
        printf("]"); 
        return;
    }
    if(verbose == 2){
        printf("- TCP, Src Port : %d, Dst Port : %d", ntohs(tcp_info->th_sport),ntohs(tcp_info->th_dport));
        printf(" [ ");
        if(fin)  printf("FIN ");
        if(syn)   printf("SYN ");
        if(rst) printf("RST ");
        if(push) printf("PSH ");
        if(ack) printf("ACK ");
        if(urg) printf("URG ");
        printf("]\n");        
        return;
    }


    printf("%*c+ TCP :\n",TSP_SPACE_HDR, ' ');
    printf("%*c| Source Port : %d\n",TSP_SPACE, ' ', *port_src);
    printf("%*c| Destination Port : %d\n",TSP_SPACE, ' ',*port_dst);
    printf("%*c| Sequence number : %d\n",TSP_SPACE, ' ',seq);
    printf("%*c| Ack number : %d\n",TSP_SPACE, ' ',ack_seq);
    printf("%*c| Data Offset : %d\n",TSP_SPACE, ' ', data_offset );
    printf("%*c| Flags :\n",TSP_SPACE, ' ');
    printf("%*c  - FIN : %d\n",TSP_SPACE, ' ',fin);
    printf("%*c  - SYN : %d\n",TSP_SPACE, ' ',syn);
    printf("%*c  - RST : %d\n",TSP_SPACE, ' ',rst);
    printf("%*c  - PSH : %d\n",TSP_SPACE, ' ',push);
    printf("%*c  - ACK : %d\n",TSP_SPACE, ' ',ack);
    printf("%*c  - URG : %d\n",TSP_SPACE, ' ',urg);
    printf("%*c| Window : %d\n",TSP_SPACE, ' ',window);
    printf("%*c| Checksum : %d\n",TSP_SPACE, ' ',cksum);
    printf("%*c| Urgent Pointer : %d\n",TSP_SPACE, ' ',urg_pointer);
    printf("%*c+____\n",TSP_SPACE, ' ');
    printf("\n");
}