#include "arp_lib.h"


struct __attribute__((packed)) rs_packet
{
	struct ether_header eth_header;
	struct arphdr arp;
	struct __attribute__((packed)) arp_data
	{
		uint8_t sha[6];
		uint32_t sip;
		uint8_t dha[6];
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

	ioctl(s,SIOCGIFADDR, &ifr);
	IP_addr->s_addr = *(uint32_t*)(ifr.ifr_addr.sa_data+2);

}

void rs_ARP(pcap_t* handle, uint8_t MAC_addr[6],uint8_t dest_MAC[6] ,struct in_addr* IP1, struct in_addr* IP2, int mode)
{
	struct rs_packet p;
	const u_char *stream;
	stream = (const u_char*)&p;
	memcpy(p.eth_header.ether_dhost,dest_MAC,6);
	memcpy(p.eth_header.ether_shost,MAC_addr,6);
	p.eth_header.ether_type = htons(0x0806);

	p.arp.ar_hrd = htons(1);
	p.arp.ar_pro = htons(0x0800);
	p.arp.ar_hln = (uint8_t)6;
	p.arp.ar_pln = (uint8_t)4;
	p.arp.ar_op = htons((uint16_t)mode);


	memcpy(p.data.sha,MAC_addr,6);
	p.data.sip = IP1->s_addr;
	memset(p.data.dha,0xff,6);
	p.data.dip = IP2->s_addr;


	pcap_sendpacket(handle,stream,sizeof(struct rs_packet));
}
	
void get_senders_mac(pcap_t *handle, struct in_addr* sender_IP, uint8_t MAC_addr[6])
{
	struct pcap_pkthdr *header;
	const u_char *p_data;
	struct rs_packet *p;


	while(1)
	{
		pcap_next_ex(handle, &header, &p_data);
		p = (struct rs_packet*)p_data;
		if(ntohs((p->eth_header).ether_type) == 0x0806)
		{
			if((p->data).sip == sender_IP->s_addr)
			{
				printf("[*] detected sender's ARP!\n");
				memcpy(MAC_addr,(p->data).sha,6);
				break;
			}
		}
	}
}
