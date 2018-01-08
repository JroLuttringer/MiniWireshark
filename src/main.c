#include "../include/packet_processing.h"


int verbose = 3;


void got_packet(u_char* not_used, const struct pcap_pkthdr* header,
                const u_char* packet) {
  (void)not_used;
  int network_id   = 0;
  int transport_id = 0;
  int port_dst = 0;
  int port_src = 0;
  int length = 0;
  int total_length = 0;
  static int nb_pqt = 1;

  // Petite séparation si nécessaire
  if(verbose != 1)
    printf("\n======== Received packet #%d ====================================================================== \n\n",nb_pqt++);
  else 
    printf("#%4d:  ",nb_pqt++);

  // afficher le paquet en hexa si nécessaire
  if(verbose == 3)
    packet_to_hexa(packet, header);

  // Process ethernet, décaler le pointeur, et process la couche réseau
  process_ethernet(packet, &network_id, verbose);
  packet += sizeof(struct ether_header);
  total_length += sizeof(struct ether_header);

  // process la couche réseau 
  process_network_layer(packet, network_id, &transport_id, verbose);

  // Process transport layer or ICMP
  if(ntohs(network_id) == ETHERTYPE_IP){
    // Si on a traité de l'ip, on décale le pointeur de la taille de l'entete ip
    packet += sizeof(struct ip);
    total_length += sizeof(struct ip);
    // si la couche suivant est de l'ICMP, on process l'icmp
    if(transport_id == ICMP){
      process_icmp(packet, verbose);
      packet += sizeof(struct icmphdr)+8;
      if(verbose > 1)
        print_data(packet);
    
    } else {
      // Sinon, on process la couche transport
      process_transport_layer(packet, transport_id, &port_src, &port_dst, &length, verbose);
      // on décale le pointeur sur le début de la couche application
      packet += length;
      total_length += length;
      // on traite la couche application
      process_app(packet, port_src, port_dst, header->len - total_length, verbose);
    }
  }

  if(verbose != 1)
    printf("\n===================================================================================================");
  printf("\n");
 
}


void print_help() {
  printf("Usage: ./packet_analyser [OPTIONS]\n");
  printf("Options : \n");
  printf("\t -i <ifname>\n");
  printf("\t -o <file to read> (offline analysis)\n");
  printf("\t -f <filter> \n");
  printf("\t -v <verbosity> \n");
  printf("\t -h : Print this help\n");
  printf("NOTE : i and o options can't be set simultaneously\n");
}

void print_usage() {
  printf("Error while parsing options \n");
  print_help();
}

int main(int argc, char** argv) {
  char error_buffer[PCAP_ERRBUF_SIZE];
  char* dev = NULL;
  char* filter = NULL;
  char* file_in = NULL;
  pcap_t* fd = NULL;
 // int verbose = 3;
  int c;
  while ((c = getopt(argc, argv, "i:o:f:v:h")) != -1) {
    switch (c) {
      case 'i':
        if (file_in != NULL) {
          print_usage();
          exit(EXIT_FAILURE);
        }
        dev = strdup(optarg);
        break;
      case 'o':
        if (dev != NULL) {
          print_usage();
          exit(EXIT_FAILURE);
        }
        file_in = strdup(optarg);
        break;
      case 'f':
        filter = strdup(optarg);
        break;
      case 'v':
        verbose = atoi(optarg);
        break;
      case 'h':
        print_help();
        exit(EXIT_SUCCESS);
        break;
      default:
        print_usage();
        exit(EXIT_FAILURE);
    }  // end switch
  }    // end while getopt

  // no file -> live capture
  if (file_in == NULL) {
    if (dev == NULL) {
      dev = pcap_lookupdev(error_buffer);
      if (!dev) {
        printf("Error : default interface not found : \n %s \n", error_buffer);
        exit(EXIT_FAILURE);
      }
    }
    fd = pcap_open_live(dev, MAX_BYTE, PROMISC_MODE, 0, error_buffer);
    if (!fd) {
      printf("Error while opening interface %s :\n %s \n", dev, error_buffer);
      exit(EXIT_FAILURE);
    }
    if (!filter) {
      printf("Launching live capture on %s, no filter, verbosity %d \n", dev,
             verbose);
    } else {
      printf("Launching live capture on %s, filter : %s, verbosity %d \n", dev,
             filter, verbose);
    }

    // Offline capture
  } else {
    fd = pcap_open_offline(file_in, error_buffer);
    if (!fd) {
      printf("Error while opening file for offline analysis\n");
      exit(EXIT_FAILURE);
    }
    printf("Launching offline reading on %s, filter : %s, verbosity %d \n",
           file_in, filter, verbose);
  }

  if (filter) {
    struct bpf_program filter_bpf;
    bpf_u_int32 subnet_mask = 0;
    if (pcap_compile(fd, &filter_bpf, filter, 0, subnet_mask) == -1 ||
        pcap_setfilter(fd, &filter_bpf)) {
      printf("Error while setting filter. (Check filter syntax ?) \n");
      exit(EXIT_FAILURE);
    }
  }

  pcap_loop(fd, -1, got_packet, NULL);
  if(dev) free(dev);
  pcap_close(fd);
  if(filter) free(filter);
  if(file_in) free(file_in);
  return 0;
}
