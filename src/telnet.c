#include "../include/telnet.h"


void process_telnet(const u_char* packet, int data_size){
  int i = 0;
  printf("TELNET: \n");
  while (i < data_size){
    if(packet[i] == IAC) {
        i++; // carac IAC lu & afficher commande
        display_command(packet[i]);

        // Si subnegoc, afficher la subnegoc
        if(packet[i]==SB){
          display_option(packet[++i]);
          while(!(packet[i]==IAC) && packet[i+1] == SE)
            printf(" %d", packet[i++]);
          printf("\n");
        // sinon affichier l'option
        } else {
          i++; // on option
          display_option(packet[i]);
        }
    }
  }
}


void display_command(u_char command){
  printf("(%d)", command);
  switch(command){
    case SE:
      printf(" end of subnegociation");
      break;
    case NOP:
      printf(" No operation");
      break;
    case DM:
      printf(" Data Mark");
      break;
    case BRK:
      printf(" Break");
      break;
    case IP:
      printf(" Interrupt current process");
      break;
    case AO:
      printf(" Abort Output");
      break;
    case AYT:
      printf(" Are you there ?");
      break;
    case GA:
      printf(" Go Ahead");
      break;
    case SB:
      printf(" Subnegociation Begin");
      break;
    case WILL:
      printf(" Will");
      break;
    case WONT:
      printf(" Won't");
      break;
    case EC:
      printf(" Erase Char");
      break;
    case EL:
      printf(" Erase Line");
      break;
    default:
      printf(" Not supported");
  }
}

void display_option(u_char option){
  printf("(%d)",option );
  switch(option){
    case ECHO:
      printf(" Echo");
      break;
    case SUPP_GO_AHEAD:
      printf(" Suppress Go Ahead");
      break;
    case STATUS:
      printf(" Status");
      break;
    case TIM_MARK:
      printf(" Timing Mark");
      break;
    case TERM_TYPE:
      printf(" Terminal type");
      break;
    case WIN_SIZE:
      printf(" Window Size");
      break;
    case TERM_SPEED:
      printf(" Terminal Speed");
      break;
    case REM_FLOW_CTRL:
      printf(" Remote Flow Control");
      break;
    case LINEMODE:
    printf(" Linemode");
      break;
    case ENV_VAR:
      printf(" Env. variable");
      break;
    case RECONNECT:
      printf(" Reconnect");
      break;
    case LINE_WIDTH:
      printf(" Line Width");
      break;
    default:
      printf(" Not supported");
  }
}
