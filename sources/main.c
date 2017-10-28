#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <check.h>
#define MAX_BYTE 15000
#define PROMISC_MODE 1

pcap_if_t* chose_dev(){
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t *interfaces, *temp;
    int i=0;
    int selected_dev = 0;
	pcap_if_t* dev;
    
    CHECK( pcap_findalldevs(&interfaces,error_buffer) !=-1 );
	
    printf("\nInterfaces found :");
    for(temp=interfaces; temp!=NULL ; temp=temp->next)
        printf("\n-%d : %s",i++,temp->name);
    i=0;
    
    printf("Chose dev\n");
    scanf("%d", &selected_dev);
	for(temp=interfaces; temp!=NULL ; temp=temp->next){
		if( i==selected_dev )
			dev = temp;
		i++;
	}

	return dev;

}



void got_packet(u_char* args, const struct pcap_pkthdr * header, const u_char *packet){
	printf("\n================= Received packet ======================== \n");
	int i = 0;
	 for (i = 0; i < header->len; i ++) {
		if( i%15 == 0) printf("\n");
        printf(" %02x", packet[i]);
    }
    printf("\n\n");
    const struct ether_header *ethernet; 
	const struct ip *ip; 
	int size_ethernet = sizeof(struct ether_header); 
	ethernet = (struct ether_header*)(packet);
	ip = (struct ip*)(packet + size_ethernet);
	
	printf("\nEthernet :\n");
	printf("\tSource : ");
    int m = 0;
    for (m =0 ; m<6;m++){
		printf("%02x", ethernet->ether_shost[m]);
		if(m != 5) printf(":");
	}
	printf("\n\tDestination : ");
	for (m =0 ; m<6;m++){
		printf("%02x", ethernet->ether_dhost[m]);
		if(m != 5) printf(":");
	}

	printf("\n\tType : %02x \n", ethernet->ether_type); 
	
	printf("IP :\n");
	printf("\tIHL : %d \n\tVersion : %d \n\tToS : %d \n\tLength : %d \n" , 
		ip->ip_hl, ip->ip_v, ip->ip_tos, ip->ip_len );
	printf("\tID : %d \n\tOffset : %d \n\tttl : %d \n\tProtocol : %d \n\tChecksum : %d\n", 
		ip->ip_id, ip->ip_off, ip->ip_ttl, ip->ip_p, ip->ip_sum );
	
	struct in_addr ip_src, ip_dst;
	ip_src = ip->ip_src;
	ip_dst = ip->ip_dst;
	printf("\tSource : %s\n", inet_ntoa(ip_src));
	printf("\tDest : %s\n", inet_ntoa(ip_dst));
	
	
	
    printf("============================================================");
    printf("\n");
}


int main(int argc, char **argv){
	char error_buffer[PCAP_ERRBUF_SIZE];
	pcap_if_t* dev = chose_dev();	
	printf(" Interface : %s\n", dev->name);
	pcap_t* dev_fd = pcap_open_live(dev->name, MAX_BYTE, PROMISC_MODE, 0, error_buffer);
	//TODO: Exit si erreur?
	bpf_u_int32 * ip_dev = NULL;
	bpf_u_int32 * subnet_mask = NULL;
	pcap_lookupnet( dev->name, &ip_dev, &subnet_mask , error_buffer);
	struct bpf_program* filtre ;
	CHECK(pcap_compile(dev_fd, filtre, "ip", 0, subnet_mask) != -1);
	pcap_setfilter( dev_fd, filtre);
	pcap_loop(dev_fd, -1, got_packet, NULL);
	return 0;
}













