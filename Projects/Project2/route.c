/* Danny DeRuiter - CIS 457 Forwarding Project */

#include <sys/socket.h> 
#include <stdlib.h>
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

unsigned short calcCheckSum(char *data, int len);

struct arpheader{
  unsigned short int arp_head;		//format of hardware address
  unsigned short int arp_protocol;	//format of protocol address
  unsigned char arp_addrlen;			//length of hardware address
  unsigned char arp_protolen;		//length of protocol address
  unsigned short int arp_code;		//ARP opcode (command)
  
  unsigned char arp_srcHA[6];		//sender hardware address
  unsigned char arp_srcIP[4];		//sender IP address
  unsigned char arp_dstHA[6];		//target hardware address
  unsigned char arp_dstIP[4];		//target IP address 
};

struct ipheader{
  unsigned char misc[8];
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned char srcIP[4];
  unsigned char dstIP[4];
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
  int router_num = 0;
  struct ip_addr ips[10];
  int nbrips = 0;
  fd_set sockets;
  FD_ZERO(&sockets);
  //get list of interfaces (actually addresses)
  struct ifaddrs *ifaddr, *tmp;
   struct mac_addr macs[10];
   int nbrmacs = 0;
   
   
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
		ips[nbrips] = address;
		nbrips++;
    }
		
	if(tmp->ifa_addr->sa_family==AF_PACKET)
	{
		printf("Interface: %s\n",tmp->ifa_name);
		//create a packet socket on interface r?-eth1
		if(!strncmp(&(tmp->ifa_name[3]),"eth",3))
		{
			printf("Creating Socket on interface %s\n",tmp->ifa_name);
				if(!strncmp(&(tmp->ifa_name[0]),"r1",2))
				{
					router_num = 1;
				}
				if(!strncmp(&(tmp->ifa_name[0]),"r2",2))
				{
					router_num = 2;
				}
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
			printf("Packet Socket: %d\n", packet_socket);
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
			
			//add mac addr
			struct mac_addr mac;
			mac.sock_id = packet_socket;
			mac.socket = (struct sockaddr_ll*)tmp->ifa_addr;
			strcpy(mac.inf_name,tmp->ifa_name);
			macs[nbrmacs] = mac;
			nbrmacs++;
			//add socket to set
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
					int n = recvfrom(sock, buf, 1500,0,(struct sockaddr*)&recvaddr, &recvaddrlen);
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
						 if(ntohs(arpheader.arp_code) == 1)
						 {
							 printf("Received an ARP request\n");
							 int srcIP,dstIP;
							 //set the source ip
						     memcpy(&srcIP,arpheader.arp_srcIP,4);
							 //set the target ip
							 memcpy(&dstIP,arpheader.arp_dstIP,4);
							 
							 int i;
							 //check each of our IPs
							 for(i = 0; i < nbrips; i++)
							 {
								//if this is one of our own IPs
								if(ips[i].ip == dstIP) 
								{
									//2 indicates a response
									arpheader.arp_code = htons(2);
									//set the target mac
									memcpy(arpheader.arp_dstHA,arpheader.arp_srcHA,6);
									
									//set target IPs
									unsigned char ip[4];
									memcpy(ip,arpheader.arp_srcIP,4);
									//set the source ip to the target ip (our own)
									memcpy(arpheader.arp_srcIP,arpheader.arp_dstIP,4);
									//set the target ip to the source ip
									memcpy(arpheader.arp_dstIP,ip,4);
									
									//fill in our mac address
									int k;
									for(k=0;k<nbrmacs;k++)
									{
										//same sock means same machine
										if(i == macs[k].sock_id)
										{
											struct sockaddr_ll mysock = *macs[k].socket;
											memcpy(arpheader.arp_srcHA,mysock.sll_addr,6);
											
											//set ethernet source and destination
											memcpy(ethheader.ether_shost,mysock.sll_addr,6);
											memcpy(ethheader.ether_dhost,recvaddr.sll_addr,6);
										}
									}
									
									//copy our ethernet and arp changes back to buffer
									memcpy(buf,&ethheader,12);
									memcpy(&buf[14],&arpheader,28); 
									printf("Sending ARP response...\n");
									if(send(sock, buf, 42, 0) < 0)
									{
										fprintf(stderr, "Error sending ARP response...\n");
									}
								}
								else
								{
									//need to handle this if it's not one of our own IPs
									printf("Not our IP\n");
								}
							 }
						 }
						
					}
					else if(ethheader.ether_type == ETHERTYPE_IP)
					{
						//copy the dest IP into the ip header
						memcpy(&ipheader,&buf[14],20);
						int dstIP;
						//copy the destination ip into the target ip
						memcpy(&dstIP,ipheader.dstIP,4);
						
						int i;
						for(i = 0; i < nbrips; i++)
						{
							//if the ip belongs to us
							 if(ips[i].ip==dstIP)
							 {
								 //if ICMP
								 if(ipheader.protocol == 1)
								 {
									 printf("ICMP\n");
									 
									 //setting eth source and dest
									 unsigned char tempmac[6];
									 memcpy(tempmac, ethheader.ether_shost, 6);
									 //swap addrs
									 memcpy(ethheader.ether_shost, ethheader.ether_dhost, 6);
									 memcpy(ethheader.ether_dhost, tempmac, 6);
									 
									 //change ip header src and dest
									 unsigned char tempip[4];
									 memcpy(tempip, ipheader.srcIP, 4);
									 memcpy(ipheader.srcIP, ipheader.dstIP, 4);
									 memcpy(ipheader.dstIP, tempip, 4);
									 
									 //set type (starts at pos 34)
									 memset(&buf[34], 0, 2);
									 
									 //copy into buf
									 memcpy(buf, &ethheader, 12);
									 memcpy(&buf[14], &ipheader, 20);
									 
									 printf("Sending ICMP response...\n");
									 response_sent = 1;
									 if(send(sock, buf, 98, 0) == -1)
									 {
										fprintf(stderr, "Failed to send ICMP response\n");
									 }
									else
									{
										printf("Not ICMP\n");
									}
								 }
							 }
						}
						//this is not one of our IPs, time to forward
						printf("Not one of our IPs\n");
						FILE *fp;
						char line[50];
						char prefix[9];
						char destination[9];
						char interface[8];
						
						//check routing table
						if(router_num == 1)
						{
							fp = fopen("r1-table.txt", "r");
							printf("Checking r1-table.txt...\n");
						}
						else if(router_num == 2)
						{
							fp = fopen("r2-table.txt", "r");
							printf("Checking r2-table.txt...\n");
						}
						//this should really never happen
						else
						{
							exit(1);
						}
						//begin looping through lookup table
						while(fgets(line, 50, fp) != NULL)
						{
							int prefixInt, targetCheck, prefixCheck;
							memcpy(prefix, line, 8);
							prefix[8] = '\0';
							//copy ip from table
							prefixInt = inet_addr(prefix);
							targetCheck = 0;
							prefixCheck = 0;
							
							memcpy(&targetCheck, &dstIP, 3);
							memcpy(&prefixCheck, &prefixInt, 3);
							if(targetCheck == prefixCheck)
							{
								printf("Found IP in routing table\n");
								memcpy(destination, &line[12], 8);
								
								if(!strncmp(destination, "-", 1))
								{
									printf("Destination is target IP of packet\n");
									memcpy(interface, &line[14], 7);
								}
								else
								{
									memcpy(interface, &line[21], 7);
									destination[8] = '\0';
									dstIP = inet_addr(destination);
									printf("Destination is %s\n", destination);
								}
								
								interface[7] = '\0';
								int k;
								for(k = 0; k < nbrmacs; k++)
								{
									 if(!strncmp(interface,macs[k].inf_name,8))
									 {
										 printf("Found interface in routing table...\n");
										 //set timeout for 2 seconds
										 struct timeval timeout={0,1}; 
										 setsockopt(macs[k].sock_id,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(struct timeval));
										
										//construct ARP request header
										struct arpheader arprequest;
										arprequest.arp_head = htons(1);
										arprequest.arp_protocol = htons(2048);
										arprequest.arp_addrlen = 6;
										arprequest.arp_protolen = 4;
										arprequest.arp_code = htons(1);
										
										struct sockaddr_ll mysock = *macs[k].socket;
										memcpy(arprequest.arp_srcHA, mysock.sll_addr, 6);
										int m, arpsender;
										//look for the inf name
										for(m = 0; m < nbrips; m++)
										{
											if(!strncmp(macs[k].inf_name, ips[m].inf_name, 8))
											{
												arpsender = ips[m].ip;
											}
										}
										memcpy(arprequest.arp_srcIP, &arpsender, 4);
										
										//set targeet hardware to all zero
										memset(arprequest.arp_dstHA, 0, 6);
										
										//set target IP
										int arptarget = dstIP;
										memcpy(arprequest.arp_dstIP, &arptarget, 4);
										
										//eth header
										struct ether_header ethrequest;
										memset(ethrequest.ether_dhost, 255, 6);
										memcpy(ethrequest.ether_shost, mysock.sll_addr, 6);
										ethrequest.ether_type = htons(ETHERTYPE_ARP);
										
										//buffer to send
										char buffer[42];
										memcpy(buffer, &ethrequest, 14);
										memcpy(&buffer[14], &arprequest, 28);
										
										//send the request
										if(send(macs[k].sock_id, buffer, 42, 0) < 0)
										{
											printf("Send has failed\n");
										}
										else
										{
											printf("Sent ARP request\n");											
										}

										
										//wait for reply
										int recvlen = recvfrom(macs[k].sock_id, buffer, 42, 0, (struct sockaddr*)&recvaddr, &recvaddrlen);
										
										if(recvlen < 0)
										{
											//TODO: variable length
											//ARP REPLY TIMEOUT
											//set ethernet header
											char errorBuf[100]={0};
											memcpy(errorBuf, ethheader.ether_shost, 6);
											memcpy(&errorBuf[6], ethheader.ether_dhost, 6);
											memcpy(&errorBuf[12], &buf[12], 2);
											
											//put current ip header into data section
											int padSet = 0;
											memcpy(&errorBuf[38], &padSet, 4);
											memcpy(&errorBuf[42], &ipheader, 20);
											memcpy(&errorBuf[62], &buf[34], 84);
											
											
											//set ip header
											unsigned short dataLen = htons(104);
											memcpy(&ipheader.misc[2], &dataLen, 2);
											ipheader.ttl = 64;
											memcpy(ipheader.dstIP, ipheader.srcIP, 4);
											memcpy(ipheader.srcIP, &ips[2].ip, 4);
											//Calculate ipheader checksum
											ipheader.checksum = 0;
											ipheader.protocol = 1;
											char buff[20];
											memcpy(buff,&ipheader,20);
											//unsigned short ourSum = calcCheckSum(buff,20);   
											//ipheader.checksum = ourSum;
											
											memcpy(&errorBuf[14], &ipheader, 20);
											
											//set icmp
											errorBuf[34] = 3;
											errorBuf[35] = 1;
											char buff2[20];
											memcpy(buff2,&errorBuf[34], 32);
											//unsigned short ourSum2 = calcCheckSum(buff2,32);   
											//memcpy(&errorBuf[36], &ourSum2, 2);
											
											printf("Send ICMP ARP timeout Error\n");
											response_sent = 1;
											send(i, errorBuf, 118, 0);
										}
										else
										{
											printf("Received ARP reply\n");
											
											//update ether header with correct mac_addr
											struct ether_header ethforward;
											memcpy(ethforward.ether_dhost, &buffer[6], 6);
											memcpy(ethforward.ether_shost, ethrequest.ether_shost, 6);
											
											ipheader.ttl --;
											
											if(ipheader.ttl < 1)
											{
												//send ICMP error 
												
												//set eth header
												char errorBuf[100] = {0};
												memcpy(errorBuf, ethheader.ether_shost, 6);
												memcpy(&errorBuf[6], ethheader.ether_dhost, 6);
												memcpy(&errorBuf[12], &buf[12], 2);
												
												//put ip header into data layer
												int padSet = 0;
												memcpy(&errorBuf[38], &padSet, 4);
												memcpy(&errorBuf[42], &ipheader, 20);
												memcpy(&errorBuf[62], &buf[12], 2);
												
												//set ip header
												unsigned short dataLen = htons(104);
												memcpy(&ipheader.misc[2], &dataLen, 2);
												ipheader.ttl = 64;
												memcpy(ipheader.dstIP, ipheader.srcIP, 4);
												memcpy(ipheader.srcIP, &ips[2].ip, 4);
												
												//checksum
												ipheader.checksum = 0;
												ipheader.protocol = 1;
												char buff[20];
												memcpy(buff, &ipheader, 20);
												unsigned short ourSum = calcCheckSum(buff, 20);
												ipheader.checksum = ourSum;
												
												memcpy(&errorBuf[14], &ipheader, 20);
												
												//set icmp
												errorBuf[34] = 11;
												errorBuf[35] = 0;
												char buff2[20];
												memcpy(buff2, &errorBuf[34], 32);
												unsigned short ourSum2 = calcCheckSum(buff2, 32);
												memcpy(&errorBuf[36], &ourSum2, 2);
												
												if(send(i, errorBuf, 118, 0) < 0)
												{
													fprintf(stderr, "Error sending ICMP Time Exceeded Error.\n");
												}
												else
												{
													response_sent = 1;
													printf("Sent ICMP eime exceeded error message.\n");
												}
											}
											
											ipheader.checksum = 0;
											char buff[20];
											
											memcpy(buff,&ipheader,20);
											unsigned short ourSum = calcCheckSum(buff,20);   
											ipheader.checksum = ourSum;
											
											memcpy(buf, &ethforward, 12);
											memcpy(&buf[14], &ipheader, 20);
											
											int sendCheck; 
											if(send(macs[k].sock_id, buf, n, 0) < 0)
											{
												fprintf(stderr, "Failed to forward packet.\n");
											}
											else
											{
												printf("Packet has been forwarded.\n");
												response_sent = 1;
											}
										}
									 }
								}
							}
						}
						if(response_sent == 0)
						{
							printf("Not in routing table file.\n");
							
							//send ICMP error network unreachable
							char errorBuf[100] = {0};
							memcpy(errorBuf, ethheader.ether_shost, 6);
							memcpy(&errorBuf[6], ethheader.ether_dhost, 6);
							memcpy(&errorBuf[12], &buf[12], 2);
							
							//put ip into data layer
							int padSet = 0;
							memcpy(&errorBuf[38], &padSet, 4);
							memcpy(&errorBuf[42], &ipheader, 20);
							memcpy(&errorBuf[62], &buf, 84);
							
							//set ip header
							unsigned short dataLen = htons(104);
							memcpy(&ipheader.misc[2], &dataLen, 2);
							ipheader.ttl = 64;
							memcpy(ipheader.dstIP, ipheader.srcIP, 4);
							memcpy(ipheader.srcIP, &ips[2].ip, 4);
							
							//ip header checksum
							ipheader.checksum = 0;
							ipheader.protocol = 1;
							char buff[20];
							memcpy(buff, &ipheader, 20);
							unsigned short ourSum = calcCheckSum(buff, 20);
							ipheader.checksum = ourSum;
							
							//put the ip header in the buff
							memcpy(&errorBuf[14], &ipheader, 20);
							
							//set ICMP
							errorBuf[34] = 3;
							errorBuf[35] = 0;
							char buff2[20];
							memcpy(buff2, &errorBuf[34], 32);
							unsigned short ourSum2 = calcCheckSum(buff2, 32);
							memcpy(&errorBuf[36], &ourSum2, 2);
							
							if(send(i, errorBuf, 118, 0) < 0)
							{
								fprintf(stderr, "Failed to send ICMP network unreachable error.\n");
							}
							else
							{
								response_sent = 1;
								printf("Sent ICMP network unreachable error.\n");
							}
						}
					}
				}
			}
		}
  //exit
  return 0;
}

unsigned short calcCheckSum(char *data, int len)
{
	unsigned int sum = 0;
	int i;
	
	//build checksum
	for(i = 0; i < len - 1; i+= 2)
	{
		unsigned short temp = *(unsigned short *) &data[i];
		sum += temp;
	}
	
	while(sum >> 16)
	{
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	
	return ~sum;
}