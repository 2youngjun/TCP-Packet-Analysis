#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#define ETHER_ADDR_LEN 6

/*
 *  Ethernet header
 */
typedef struct ethernet_hdr
{
    u_int8_t  ether_dhost[ETHER_ADDR_LEN];/* destination ethernet address */
    u_int8_t  ether_shost[ETHER_ADDR_LEN];/* source ethernet address */
    u_int16_t ether_type;                 /* protocol */
}EtherHDR;


/*
 *  IPv4 header
 */
typedef struct ipv4_hdr
{
    u_int8_t ip_v:4,       /* version */
           ip_hl:4;        /* header length */
    u_int8_t ip_tos;       /* type of service */
    u_int16_t ip_len;         /* total length */
    u_int16_t ip_id;          /* identification */
    u_int16_t ip_off;
    u_int8_t ip_ttl;          /* time to live */
    u_int8_t ip_p;            /* protocol */
    u_int16_t ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
}IPv4HDR;

/*
 *  TCP header
 */
typedef struct tcp_hdr
{
    u_int16_t th_sport;       /* source port */
    u_int16_t th_dport;       /* destination port */
    u_int32_t th_seq;          /* sequence number */
    u_int32_t th_ack;          /* acknowledgement number */
    u_int8_t th_off:4;		 /* data offset */
	u_int8_t th_win;		/* window */
    u_int16_t th_sum;         /* checksum */
    u_int16_t th_urp;         /* urgent pointer */
}TcpHDR;

void print_mac_addr(EtherHDR* ether_hdr) {

	u_int8_t *src = ether_hdr -> ether_shost;
	u_int8_t *dst = ether_hdr -> ether_dhost;

	printf("[Ethernet Header]\n");

	printf("Source MAC: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", src[0], src[1], src[2], src[3], src[4], src[5]);

	printf("Destination MAC: ");
	printf("%02X:%02X:%02X:%02X:%02X:%02X\n", dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
}

void print_ip_addr(IPv4HDR* ip_hdr) {
	struct in_addr src = ip_hdr -> ip_src;
	struct in_addr dst = ip_hdr -> ip_dst;

	printf("[IP Header]\n");

	printf("Source IP: ");
	printf("%u.%u.%u.%u\n", (src.s_addr >> 0) & 0xFF, (src.s_addr >> 8) & 0xFF, (src.s_addr >> 16) & 0xFF, (src.s_addr >> 24) & 0xFF);

	printf("Destination IP: ");
	printf("%u.%u.%u.%u\n", (dst.s_addr >> 0) & 0xFF, (dst.s_addr >> 8) & 0xFF, (dst.s_addr >> 16) & 0xFF, (dst.s_addr >> 24) & 0xFF);
}

void print_tcp_addr(TcpHDR* tcp_hdr){
	u_int16_t src = ntohs(tcp_hdr -> th_sport);
	u_int16_t dst = ntohs(tcp_hdr -> th_dport);

	printf("[TCP Header]\n");

	printf("Source PORT: %u\n", src);
	printf("Destination PORT: %u\n", dst);
}

void print_payload(const u_char* payload, u_int8_t len) {
	printf("[Payloads]\n");
	if(len > 10)
		len = 10;
	for(u_int8_t i=0; i<len; i++)
		printf("%02X ", *(payload+i));
	printf("\n----------------------------------");
	printf("\n\n");
}

/* Check IPv4 Header is 0x06(TCP) */
bool isTCP(IPv4HDR* ip_hdr){
	return ip_hdr -> ip_p == 0x06 ? true : false;
}

/* Check Ethernet Header Type is 0x0800(IPv4) */
bool isIPv4(EtherHDR* ether_hdr){
	return ntohs(ether_hdr->ether_type) == 0x0800 ? true : false;
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	EtherHDR *ethernet;
	IPv4HDR *ip;
	TcpHDR *tcp;

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		ethernet = (EtherHDR*) packet;
		ip = (IPv4HDR*)(packet + 14);
		/* IP Header Length: ip_hl 하위 4bit 비트 마스킹 * 4(byte) */ 
		u_int8_t ip_hdr_len = (ip -> ip_hl & 0x0F) * 4;

		tcp = (TcpHDR*)(packet + 14 + ip_hdr_len);
		u_int8_t tcp_hdr_len = (tcp -> th_off >> 4) * 4;

		u_int8_t all_hdr_len = 14 + ip_hdr_len + tcp_hdr_len;
		u_int8_t payload_len = (header -> len) - all_hdr_len;
		
		if (isIPv4(ethernet) && isTCP(ip)) {
			printf("%u bytes captured\n", header->caplen);
			print_mac_addr(ethernet);
			print_ip_addr(ip);
			print_tcp_addr(tcp);
			print_payload(packet + all_hdr_len, payload_len);
		}

	}

	pcap_close(pcap);
}
