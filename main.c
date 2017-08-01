#include "arp_lib.h"


int main(int argc, char* argv[])
{
	pcap_t* handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	uint8_t MAC_addr[6] = {0,};
	uint8_t senders_MAC[6] = {0,};
	struct in_addr my_IP;
	struct in_addr sender_ip;
	struct in_addr target_ip;
	
	/*	
	if(argc != 4)
	{
		printf("Usage: ./send_arp [interface] [sender_ip] [target_ip]\n");
	}
	*/
	inet_aton(argv[2],&sender_ip);
	inet_aton(argv[3],&target_ip);
	printf("sender ip : %x\n", sender_ip);
	handle = pcap_open_live(argv[1],BUFSIZ,1,1000,errbuf);
	
	get_addr(MAC_addr,&my_IP ,argv[1]);
	rs_ARP(handle,MAC_addr,&my_IP , &sender_ip,1); // request mode

	//get_senders_mac(sender, sender_ip, senders_MAC);

	rs_ARP(handle, MAC_addr, &target_ip, &sender_ip, 0); //send mode
	return 0;
}
