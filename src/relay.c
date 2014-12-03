#include "relay.h"

int main(int argc, char **argv)
{
	/* Check to see if user is root */
	if (geteuid() != USER_ROOT)
	{
		printf("\nYou need to be root to run this.\n\n");
    		exit(0);
	}

	relay_options.listen_port = DEFAULT_LISTEN_PORT;
	relay_options.dest_port = DEFAULT_DEST_PORT;
	relay_options.protocol = TCP_PROTOCOL;

	if(parse_options(argc, argv) < 0)
		exit(1);

	print_opt();
	start_relay();

	return 0;
}

int start_relay()
{
	pcap_t * nic_handle = NULL;
	struct bpf_program fp;

	startPacketCapture(nic_handle, fp, FROM_RELAY, NULL, relay_options.listen_port, 
		relay_options.client_host, relay_options.dest_port, relay_options.protocol);
	stopPacketCapture(nic_handle, fp);
	return 0;

}

int parse_options(int argc, char **argv)
{
	char c;

	while ((c = getopt (argc, argv, "a:ldp:")) != -1)
	{
		switch(c)
		{
			case 'a':
				relay_options.client_host = optarg;
				break;
			case 'd':
				relay_options.dest_port = atoi(optarg);
				break;
			case 'l':
				relay_options.listen_port = atoi(optarg);
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
			case ':':
			default:
				fprintf(stderr, "Must add a server host, dest port, and protocol.\n");
				usage(argv[0], RELAY_MODE);
				return -1;
		}
	}
	return 0;

}

void print_opt()
{
	fprintf(stderr, "Listening on port: %d\n", relay_options.listen_port);
	fprintf(stderr, "Destination port to send to: %d\n", relay_options.dest_port);
	fprintf(stderr, "Host to forward to: %s\n", relay_options.client_host);
	fprintf(stderr, "Protocol: %s\n", relay_options.protocol == TCP_PROTOCOL ? "TCP" : "UDP");
}