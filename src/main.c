#include "main.h"


int main (int argc, char **argv){
	char c;
	int port=0, server=0;
	char host[80];
	char command[BUF_LENGTH];
	
	while ((c = getopt (argc, argv, "sa:p:c:")) != -1){
		switch (c){
			case 'p':
				port= atoi(optarg);
			break;
			case 'a':
				strncpy(host, optarg,79); //probably need to use strcpy
			break;
			case 's':
				server = 1;
			break;
			case 'c':
				strncpy(command, optarg, BUF_LENGTH -1); //probably need to use strcpy
			
			case '?':
			default:
				fprintf(stderr, "Usage: %s \n", argv[0]);
				return 1;
		}
	}
	
	if(server == 0){
		
		startClient(host, port, command);
		
	} else {
		//initServer();
		//startServer();
	}
	return 0;
}
