#include "../include/http_imap_pop_smtp_ftp.h"




void process_http(const u_char* packet, int length, int is_response){
    printf("HTTP");
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_imap(const u_char* packet, int length, int is_response){
    printf("IMAP");
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_pop(const u_char* packet, int length, int is_response){
    printf("POP");
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_smtp(const u_char* packet, int length, int is_response){
    printf("SMTP");
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_ftp(const u_char* packet, int length, int is_response){
    printf("FTP");
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}