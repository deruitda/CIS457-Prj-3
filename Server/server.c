//Danny DeRuiter

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/sendfile.h>
#include <pthread.h>
void *threadListener(void *args);
int *clients;
int numClients;
/**************************************
 * Server
 *************************************/

int main(int argc, char **argv)
{
    int port;
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //get the port
    printf("Enter a port: ");
    scanf("%d", &port);
    //server is specifying its own address
    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(port);
    serveraddr.sin_addr.s_addr = INADDR_ANY;
    bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    //listens to specified socket
    listen(sockfd, 10);
    int len = sizeof(clientaddr);
    numClients = 0;
    clients = malloc(sizeof(int)*15);
		while(1)
		{
			int clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, &len);
      printf("Client Socket num: %d\n", clientsocket);
			if(clientsocket == -1)
			{
				fprintf(stderr, "Could not accept client connection...\n");
				exit(1);
			}
      clients[numClients] = clientsocket;
      numClients++;
			printf("Connection established...\n");
			//create a new child process to handle the new connection
      pthread_t listener;
      pthread_create(&listener, NULL, threadListener, &clientsocket);
      //IS THIS RIGHT??????
	   }
	return 0;
}

void *threadListener(void *args)
{
  int *clientsocket = malloc(sizeof(args));
  memcpy(clientsocket, args, sizeof(args));
  char message[LINE_MAX];
  while(recv(*clientsocket, message, sizeof(message), 0) > 0)
  {
    //printf("Message is: %s\n", message);
    if(message[0] == '-' && message[1] == 'b')
    {
      printf("Broadcasting message to all clients...\n");
      int i;
      for(i = 0; i <= numClients; i++)
      {
        //don't send to ourself
        //if(clients[i] == 4)
        //{
        //  continue;
        //}
        send(clients[i], &message[2], strlen(message), 0);
        printf("Send to client: %d\n", clients[i]);
      }
    }
     else if(message[0] == '-' && message[1] == 'l')
    {
      int i;
      char list[LINE_MAX] = "Client numbers: ";
      for(i = 0; i <= numClients; i++)
      {
        //if the client has disconnected, they cannot be contacted
        if(clients[i] == -1)
        {
          continue;
        }
        char num[5];
        sprintf(num, "%d", clients[i]);
        strcat(list, num);
        strcat(list, ", ");
      }
      printf("List: %s\n", list);
      send(*clientsocket, list, strlen(list), 0);
      printf("Sent list to client\n");
    }
    else if(message[0] == '-' && message[1] == 'm')
    {
      printf("Message: %s\n", message);
      int target = atoi(&message[2]);
      printf("Target is: %d\n", target);
      send(clients[target], &message[3], strlen(message), 0);
    }
    else
    {
      printf("Message Received: %s\n", message);
    }
    bzero(message, sizeof(message));
  }
  close(*clientsocket);
  printf("Connection closed\n");
}
