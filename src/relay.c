#include "relay.h"

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: main
-- 
-- DATE: 2014/12/02
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int main(int argc, char **argv)
-- 
-- RETURNS: 0 for ok, 1 for error
-- 
-- NOTES: main driver function for relay program
----------------------------------------------------------------------------------------------------------------------*/
int main(int argc, char **argv)
{
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
    		exit(0);
	}
	if(argc < 2)
		usage(argv[0], RELAY_MODE);

	relay_options.listen_port = DEFAULT_LISTEN_PORT;
	relay_options.dest_port = DEFAULT_DEST_PORT;
	relay_options.protocol = TCP_PROTOCOL;

	if(parse_options(argc, argv) < 0)
		exit(1);

	print_opt();
	start_relay();

	return 0;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: start_relay
-- 
-- DATE: 2014/12/02
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int start_relay()
-- 
-- RETURNS: 0 for ok, 1 for error
-- 
-- NOTES: Function that will start packet capturing
----------------------------------------------------------------------------------------------------------------------*/
int start_relay()
{
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;

	startPacketCapture(nic_handle, fp, FROM_RELAY, NULL, relay_options.listen_port, 
		relay_options.client_host, relay_options.dest_port, relay_options.protocol);
	stopPacketCapture(nic_handle, fp);
	return 0;

}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: parse_options
-- 
-- DATE: 2014/12/02
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int parse_options(int argc, char **argv)
-- 
-- RETURNS: 0 for ok, -1 for error
-- 
-- NOTES: Parsing user command line options to pass into start_relay()
----------------------------------------------------------------------------------------------------------------------*/
int parse_options(int argc, char **argv)
{
	char c;

	while ((c = getopt (argc, argv, "a:l:d:p:")) != -1)
	{
		switch(c)
		{
			case 'a':
				relay_options.client_host = optarg;
				break;
			case 'l':
				relay_options.listen_port = atoi(optarg);
				break;
			case 'd':
				relay_options.dest_port = atoi(optarg);
				break;
			case 'p':
				if(strcmp(optarg, "TCP") == 0)
					relay_options.protocol = TCP_PROTOCOL;
				if(strcmp(optarg, "UDP") == 0)
					relay_options.protocol = UDP_PROTOCOL;
				else
				{
					fprintf(stderr, "Unknown Protocol.\n");
					return -1;
				}
				break;
			case '?':
			default:
				fprintf(stderr, "Must add a server host, dest port, and protocol.\n");
				usage(argv[0], RELAY_MODE);
				return -1;
		}
	}
	return 0;

}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: print_opt
-- 
-- DATE: 2014/12/02
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void print_opt()
-- 
-- RETURNS: void
-- 
-- NOTES: Print user options on initial packet capture
----------------------------------------------------------------------------------------------------------------------*/
void print_opt()
{
	fprintf(stderr, "Listening on port: %d\n", relay_options.listen_port);
	fprintf(stderr, "Destination port to send to: %d\n", relay_options.dest_port);
	fprintf(stderr, "Host to forward to: %s\n", relay_options.client_host);
	fprintf(stderr, "Protocol: %s\n", relay_options.protocol == TCP_PROTOCOL ? "TCP" : "UDP");
}
