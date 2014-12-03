#ifndef RELAY_H
#define RELAY_H

#include "pktcap.h"
#include "utils.h"

#define DEFAULT_DEST_PORT 7000
#define DEFAULT_LISTEN_PORT 8080
#define USER_ROOT 0

struct relay
{
	char * client_host;
	int protocol;
	int listen_port;
	int dest_port;

} relay_options;

int start_relay();
int parse_options(int argc, char **argv);
void print_opt();

#endif
