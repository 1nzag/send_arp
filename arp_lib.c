#include "arp_lib.h"

struct rs_packet
{
	struct ether_header eth_header;
	struct arphdr arp;
	struct arp_data
	{
		uint8_t sha[6];
		uint8_t dha[6];
		uint32_t sip;
		uint32_t dip;
	}data;
};


void get_addr(uint8_t MAC_addr[6],struct in_addr* IP_addr,char* interface)
{
	int s,i;
	struct ifreq ifr;
	
	s = socket(AF_INET,SOCK_DGRAM,0);
	strcpy(ifr.ifr_name, interface);
	ioctl(s,SIOCGIFHWADDR, &ifr);
	for(i=0; i<6;i++)
	{
		MAC_addr[i] = ((uint8_t*)ifr.ifr_hwaddr.sa_data)[i];
	}
	IP_addr->s_addr = *(uint32_t*)(ifr.ifr_addr.sa_data+2);
}

void rs_ARP(pcap_t* handle, unsigned char MAC_addr[6], struct in_addr* IP1, struct in_addr* IP2,int mode)
{
	struct rs_packet p;
	const u_char* stream;
	stream = &p;

	memset(p.eth_header.ether_dhost,0xff,6);
	memcpy(p.eth_header.ether_shost,MAC_addr,6);
	p.eth_header.ether_type = htons(0x0806);

	p.arp.ar_hrd = htons(1);
	p.arp.ar_pro = htons(0x0800);
	p.arp.ar_hln = htons(6);
	p.arp.ar_pln = htons(4);
	p.arp.ar_op = htons(mode);


	memcpy(p.data.sha,MAC_addr,6);
	memset(p.data.dha,0xff,6);
	p.data.sip = IP1->s_addr;
	p.data.dip = IP2->s_addr;
	

	pcap_sendpacket(handle,stream,sizeof(struct rs_packet));
}
	
	

