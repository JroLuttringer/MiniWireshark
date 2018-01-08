#include "../include/http_imap_pop_smtp_ftp.h"

/*
    Les trois fonctions fonctionnent de manière indentiques;
    en indiquant le protocole, si le paquet est une réponse/
    une requêtes, puis en affichant le contenue du paquet, 
    si la verbosité est au maximum
*/


void process_http(const u_char* packet, int length, int is_response,int verbose){
    if(verbose == 1 || verbose == 2){
        printf(" - HTTP");
        if(!is_response){
            printf(" REQUEST");
        } else {
            printf(" RESPONSE");
        }
        return ;
    }
    printf("%*c+ HTTP",APP_SPACE_HDR,' ');
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_imap(const u_char* packet, int length, int is_response,int verbose){
    if(verbose == 1 || verbose == 2){
        printf(" - IMAP");
        if(!is_response){
            printf(" REQUEST");
        } else {
            printf(" RESPONSE");
        }
        return ;
    }
    
    printf("%*c+ IMAP",APP_SPACE_HDR,' ');
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_pop(const u_char* packet, int length, int is_response,int verbose){
    if(verbose == 1 || verbose == 2){
        printf(" - POP");
        if(!is_response){
            printf(" REQUEST: ");
        } else {
            printf(" RESPONSE: ");
        }
        return ;
    }
    printf("%*c+ POP",APP_SPACE_HDR,' ');
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

void process_smtp(const u_char* packet, int length, int is_response,int verbose){
    if(verbose == 1 || verbose == 2){
        printf(" - SMTP");
        if(!is_response){
            printf(" REQUEST");
        } else {
            printf(" RESPONSE");
        }
        return ;
    }
    printf("%*c+ SMTP",APP_SPACE_HDR,' ');
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}

    void process_ftp(const u_char* packet, int length, int is_response,int verbose){
    if(verbose == 1 || verbose == 2){
        printf(" - FTP");
        if(!is_response){
            printf(" REQUEST");
        } else {
            printf(" RESPONSE");
        }
        return ;
    }
    printf("%*c+ FTP",APP_SPACE_HDR,' ');
    if(!is_response){
        printf(" REQUEST: \n");
    } else {
        printf(" RESPONSE: \n");
    }
    print_ascii(packet, length);
}