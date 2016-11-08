//Danny DeRuiter

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <pthread.h>

void *threadListener(void *arg);
struct sockaddr_in serveraddr;
int sockfd, serversocket;
/**************************************
 * Client
 *************************************/
int main(int argc, char **argv)
{
    char port[20];
    char message[LINE_MAX];
    char ip_address[20];
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    char recvBuff[256];
		memset(recvBuff, '0', sizeof(recvBuff));
		//get the port first
    printf("Enter a port: ");
    fgets(port, LINE_MAX, stdin);

    //get the IP address
    printf("Enter an IP address: ");
    fgets(ip_address, LINE_MAX, stdin);

    if(sockfd < 0)
    {
      printf("There was an error creating the socket\n");
      return 1;
    }
    serveraddr.sin_family = AF_INET; //what time of socket it is
    serveraddr.sin_port = htons((atoi(port))); //this is so the server knows where to return data
    serveraddr.sin_addr.s_addr = inet_addr(ip_address);

    int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    pthread_t listener;
    pthread_create(&listener, NULL, threadListener, "");

    if(e < 0)
    {
      printf("There was an error with connecting\n");
      return 1;
    }

    int len = sizeof(serveraddr);
    serversocket = accept(sockfd, (struct sockaddr*)&serveraddr, &len);
    printf("Connected to chat server. Type '-h' for help.\n");
		while(1)
		{
			//send the file name to the server
			printf("Enter a message or type 'q' to quit: ");
			scanf("%s", message);
			if(message[0] == 'q' && strlen(message) == 1)
			{
				printf("Closing Connections...\n");
				close(sockfd);
				close(serversocket);
				exit(0);
			}
			send(sockfd, message, strlen(message), 0);
      bzero(message, sizeof(message));
      fflush(stdout);
		}

		close(sockfd);
    close(serversocket);
    return 0;
}

void *threadListener(void *arg)
{
  int len = sizeof(serveraddr);
  while(1)
  {
    char message[LINE_MAX];
    if(recv(sockfd, message, sizeof(message), 0) == 0)
    {
      printf("Server has closed the connection\n");
      exit(0);
    }

    printf("\nReceived: %s\n", message);
    bzero(message, sizeof(message));
  }
}
