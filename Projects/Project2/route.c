#include <sys/socket.h> 
#include <netpacket/packet.h> 
#include <net/ethernet.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <string.h>

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN     4
#define ARP_FRAME_TYPE  0x0806
#define ETHER_HW_TYPE   1
#define IP_PROTO_TYPE   0x0800
#define OP_ARP_REQUEST  2

struct arpheader{
  unsigned short int ar_hrd;		/* Format of hardware address.  */
  unsigned short int ar_pro;		/* Format of protocol address.  */
  unsigned char ar_hln;			/* Length of hardware address.  */
  unsigned char ar_pln;			/* Length of protocol address.  */
  unsigned short int ar_op;		/* ARP opcode (command).  */
  
  unsigned char ar_sha[6];		/* Sender hardware address.  */
  unsigned char ar_sip[4];		/* Sender IP address.  */
  unsigned char ar_tha[6];		/* Target hardware address.  */
  unsigned char ar_tip[4];		/* Target IP address.  */
};

struct ipheader{
  unsigned char stuff[8];
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned char srcip[4];
  unsigned char dstip[4];
};

struct mac_addr{
  char inf_name[8];
  int sock_id;
  struct sockaddr_ll* socket;
};

struct ip_addr{
  char inf_name[8];
  int ip;
};

int main(){
  int packet_socket;
  int num = 0;
  struct ip_addr ips[10];
  fd_set sockets;
  FD_ZERO(&sockets);
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
  if(getifaddrs(&ifaddr)==-1)
  {
		perror("getifaddrs");
		return 1;
  }
  //have the list, loop over the list
  for(tmp = ifaddr; tmp!=NULL; tmp=tmp->ifa_next)
  {
	//get a list of our own IP addresses
	if(tmp->ifa_addr->sa_family==AF_INET)
	{
		struct sockaddr_in *sa;
		struct ip_addr address;
		sa = (struct sockaddr_in *)tmp->ifa_addr;
		//char *addr=inet_ntoa(sa->sin_addr);
		int test = sa->sin_addr.s_addr;
		printf("Current IP added to list: %d\n",test);
		strcpy(address.inf_name, tmp->ifa_name);
		address.ip = test;
		ips[num] = address;
		num++;
    }
		
	if(tmp->ifa_addr->sa_family==AF_PACKET)
	{
		printf("Interface: %s\n",tmp->ifa_name);
		//create a packet socket on interface r?-eth1
		if(!strncmp(&(tmp->ifa_name[3]),"eth1",4))
		{
			printf("Creating Socket on interface %s\n",tmp->ifa_name);
			//create a packet socket
			//AF_PACKET makes it a packet socket
			//SOCK_RAW makes it so we get the entire packet
			//could also use SOCK_DGRAM to cut off link layer header
			//ETH_P_ALL indicates we want all (upper layer) protocols
			//we could specify just a specific one
			packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			if(packet_socket<0)
			{
				perror("socket");
				return 2;
			}
			
			//Bind the socket to the address, so we only get packets
			//recieved on this specific interface. For packet sockets, the
			//address structure is a struct sockaddr_ll (see the man page
			//for "packet"), but of course bind takes a struct sockaddr.
			//Here, we can use the sockaddr we got from getifaddrs (which
			//we could convert to sockaddr_ll if we needed to)
			if(bind(packet_socket,tmp->ifa_addr,sizeof(struct sockaddr_ll))==-1)
			{
				perror("bind");
			}
			FD_SET(packet_socket, &sockets);
		}
	}
  }
  
  //free the interface list when we don't need it anymore
  freeifaddrs(ifaddr);

  //loop and recieve packets. We are only looking at one interface,
  //for the project you will probably want to look at more (to do so,
  //a good way is to have one socket per interface and use select to
  //see which ones have data)
  printf("Ready to recieve now\n");
  while(1)
  {
		char buf[1500];
		struct sockaddr_ll recvaddr;
		int recvaddrlen=sizeof(struct sockaddr_ll);
		fd_set tmp_set = sockets;
		if(select(FD_SETSIZE,&tmp_set, NULL,NULL,NULL)==-1)
		{
			fprintf(stderr,"select error"); 
		}
		
		int sock;
		
		for(sock = 0; sock < FD_SETSIZE; sock++)
		{
				
				char buf[1500]={0};
				struct ether_header ethheader;
				struct ipheader ipheader;
				struct arpheader arpheader;
				int response_sent = 0;
      
      			if(FD_ISSET(sock,&tmp_set))
				{
					int n = recvfrom(packet_socket, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
					//ignore outgoing packets (we can't disable some from being sent
					//by the OS automatically, for example ICMP port unreachable
					//messages, so we will just ignore them here)
					if(recvaddr.sll_pkttype==PACKET_OUTGOING)
						continue;
					//start processing all others
					printf("Got a %d byte packet\n", n);
					//add the ethheader
					memcpy(&ethheader,buf,14);
					//set the type of the eth header
					ethheader.ether_type = ntohs(ethheader.ether_type);
					
					if (ethheader.ether_type == ETHERTYPE_ARP)
					{
						memcpy(&arpheader,&buf[14],28);
                  		//if this is an ARP request
						 if(ntohs(arpheader.ar_op) == 1)
						 {
							 printf("Received an ARP request\n");
							 int source_ip,target_ip;
							 //set the source ip
						     memcpy(&source_ip,arpheader.ar_sip,4
							 //set the target ip
							 memcpy(&target_ip,arpheader.ar_tip,4);
							 
							 int i;
							 for(i = 0; i < num; i++)
							 {
								//if this is one of our own IPs
								if(ips[i].ip == target_ip) 
								{
									//2 indicates a response
									arpheader.ar_op = htons(2);
									//set the target addr
									memcpy(arpheader.ar_tha,arpheader.ar_sha,6);
									
									//set target IPs
									unsigned char ip[4];
									memcpy(ip,arpheader.ar_sip,4);
									//set the source ip to the target ip (our own)
									memcpy(arpheader.ar_sip,arpheader.ar_tip,4);
									//set the target ip to the source ip
									memcpy(arpheader.ar_tip,ip,4);
									
									//copy our ethernet and arp changes back to buffer
									memcpy(buf,&ethheader,12);
									memcpy(&buf[14],&arpheader,28); 
									printf("Sending ARP response...\n");
									if(send(sock, buf, 42, 0) == -1)
									{
										fprintf(stderr, "Error sending ARP response...\n");
									}
								}
								else
								{
									//need to handle this if it's not one of our own IPs
									printf("Not out IP\n");
								}
							 }
						 }
						
					}
					else if(ethheader.ether_type == ETHERTYPE_IP)
					{
						//copy the buf into the ip header
						memcpy(&ipheader,&buf[14],20);
						int target_ip;
						//copy the destination ip into the target ip
						memcpy(&target_ip,ipheader.dstip,4);
						
						int i;
						for(i = 0; i < num; i++)
						{
							//if the ip belongs to us
							 if(ips[i].ip==target_ip)
							 {
								 //if ICMP
								 if(ipheader.protocol == 1)
								 {
									 printf("ICMP\n");
									 
									 //setting eth source and dest
									 unsigned char tempmac[6];
									 memcpy(tempmac, ethheader.ether_shost, 6);
									 memcpy(ethheader.ether_shost, ethheader.ether_dhost, 6);
									 memcpy(ethheader.ether_dhost, tempmac, 6);
									 
									 //change ip header src and dest
									 unsigned char tempip[4];
									 memcpy(tempip, ipheader.srcip, 4);
									 memcpy(ipheader.srcip, ipheader.dstip, 4);
									 memcpy(ipheader.dstip, tempip, 4);
									 
									 //set type which starts at pos 34
									 memset(&buf[34], 0, 2);
									 
									 //copy into buf
									 memcpy(buf, &ethheader, 12);
									 memcpy(&buf[14], &ipheader, 20);
									 
									 printf("Sending ICMP response...\n");
									 if(send(sock, buf, 98, 0) == -1)
									 {
										fprintf(stderr, "Failed to send ICMP response\n");
									 } 
								 }
							 }
						}
					}
					
					
				}
			}
		}
  //exit
  return 0;
}
