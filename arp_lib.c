#include "arp_lib.h"

struct arp_data
{
	uint8_t sha[6];
	uint32_t sip;
	uint8_t dha[6];
	uint32_t dip;
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

void rs_ARP(pcap_t* handle, uint8_t MAC_addr[6],uint8_t dest_MAC[6] ,struct in_addr* IP1, struct in_addr* IP2, int mode)
{
	struct arp_data data;
	struct ether_header eth_header;
	struct arphdr arp;
	const u_char stream[sizeof(struct arp_data) + sizeof(struct ether_header) + sizeof(struct arphdr)];
	const u_char* stream_idx;
	memcpy(eth_header.ether_dhost,dest_MAC,6);
	memcpy(eth_header.ether_shost,MAC_addr,6);
	eth_header.ether_type = htons(0x0806);

	arp.ar_hrd = htons(1);
	arp.ar_pro = htons(0x0800);
	arp.ar_hln = (uint8_t)6;
	arp.ar_pln = (uint8_t)4;
	arp.ar_op = htons((uint16_t)mode);


	memcpy(data.sha,MAC_addr,6);
	data.sip = IP1->s_addr;
	memset(data.dha,0xff,6);
	data.dip = IP2->s_addr;
	
	stream_idx = stream;
	memcpy(stream,(const u_char*)&eth_header,sizeof(struct ether_header));
	stream_idx += sizeof(struct ether_header);
	memcpy(stream_idx,(const u_char*)&arp,sizeof(struct arphdr));
	stream_idx += sizeof(struct arphdr);
	memcpy(stream_idx,(const u_char*)&data,sizeof(struct arp_data));

	pcap_sendpacket(handle,stream,sizeof(stream));
}
	
void get_senders_mac(pcap_t *handle, struct in_addr* sender_IP, uint8_t MAC_addr[6])
{
	struct pcap_pkthdr *header;
	const u_char *p_data;
	struct ether_header *eth_header;
	struct arp_data *data;

	while(1)
	{
		pcap_next_ex(handle, &header, &p_data);
		eth_header = (struct ether_header*)p_data;
		if(ntohs(eth_header->ether_type) == 0x0806)
		{
			data = (struct rs_packet*)(p_data + 14 + sizeof(struct arphdr));
			if(data->sip == sender_IP->s_addr)
			{
				printf("[*] detected sender's ARP!\n");
				memcpy(data->sha,MAC_addr,6);
				break;
			}
		}
	}
}
