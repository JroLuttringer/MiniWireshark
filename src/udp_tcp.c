#include "../include/udp_tcp.h"

void process_udp(const u_char* packet, int* port_src, int* port_dst, int* length){
    struct udphdr* udp_info = (struct udphdr*) packet;
    *port_src = ntohs(udp_info->uh_sport);
    *port_dst = ntohs(udp_info->uh_dport);
    int cksum = ntohs(udp_info->uh_sum);
    *length = ntohs(udp_info->uh_ulen);

    printf("UDP :\n");
    printf("\tSource Port : %d\n", *port_src);
    printf("\tDestination Port : %d\n", *port_dst);
    printf("\tChecksum : %d\n", cksum);
    printf("\tLength: %d\n",*length);
    
}


void process_tcp(const u_char* packet, int* port_src, int* port_dst, int* length){
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
    int seq = ntohl(tcp_info->th_seq);
    int ack_seq = ntohl(tcp_info->ack_seq);
    int data_offset = tcp_info->th_off;
    int urg_pointer = ntohs(tcp_info->th_urp);


    printf("TCP :\n");
    printf("\tSource Port : %d\n", *port_src);
    printf("\tDestination Port : %d\n",*port_dst);
    printf("\tSequence number : %d\n",seq);
    printf("\tAck number : %d\n",ack_seq);
    printf("\tData Offset : %d\n", data_offset );
    printf("\tFlags :\n");
    printf("\t\tFIN : %d\n",fin);
    printf("\t\tSYN : %d\n",syn);
    printf("\t\tRST : %d\n",rst);
    printf("\t\tPSH : %d\n",push);
    printf("\t\tACK : %d\n",ack);
    printf("\t\tURG : %d\n",urg);
    printf("\tWindow : %d\n",window);
    printf("\tChecksum : %d\n",cksum);
    printf("\tUrgent Pointer : %d\n",urg_pointer);
}