#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include <time.h>
#include <pcap.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <termios.h>
#include <libconfig.h>

#define __FAVOR_BSD
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <getopt.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <net/if.h>
#include "lib/isaac_encryption.h"

#define SERVER_MODE 0
#define CLIENT_MODE 1
#define TCP_PROTOCOL 0
#define UDP_PROTOCOL 1

unsigned short in_cksum(unsigned short *ptr, int nbytes);
unsigned short tcp_in_cksum(unsigned int src, unsigned int dst, unsigned short *addr, int length);
unsigned short in_cksum_udp(int src, int dst, unsigned short *addr, int len);
char * get_line (char *s, size_t n, FILE *f);
void usage(char * program_name, int mode);
void send_packet(char * data, int protocol, int data_len, const char * src_ip, const char * dest_ip, int dest_port);
void craft_tcp_packet(unsigned char * packet, char * data, int data_len, struct ip iph, struct tcphdr tcp, int dest_port);
void craft_udp_packet(unsigned char * packet, char * data, int data_len, struct ip iph, struct udphdr udp, int dest_port);
char * get_ip_addr(char * network_interface);
char * xor_cipher(char * string, int string_length);

#endif
