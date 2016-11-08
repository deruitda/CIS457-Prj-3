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
  //copy the socket num
  int *clientsocket = malloc(sizeof(args));
  memcpy(clientsocket, args, sizeof(args));

  //message to be received
  char message[LINE_MAX];
  while(recv(*clientsocket, message, sizeof(message), 0) > 0)
  {
    if(message[0] == '-' && message[1] == 'h')
    {
      char *helpmsg = "\nList of available commands: \n\nList connected client numbers: -l\nSend message to all clients: -b \nSend message to specific client: -m# (# symbol represents the client number)\n\n";
      send(*clientsocket, helpmsg, strlen(helpmsg), 0);
    }
    //if the client sends a broadcast with -b
    else if(message[0] == '-' && message[1] == 'b')
    {
      printf("Broadcasting message to all clients...\n");
      int i;
      for(i = 0; i <= numClients; i++)
      {
        send(clients[i], &message[2], strlen(message), 0);
        printf("Sent to client: %d\n", clients[i]);
      }
    }
    else if(message[0] == '-' && message[1] == 'k')
    {
      int i;
      int target = atoi(&message[2]);
      int clientNum = -1;
      for(i = 0; i < numClients; i++)
      {
        if(clients[i] == target)
        {
          clientNum = clients[i];
        }
      }

      char *msg = "Client kicked from server.";
      send(*clientsocket, msg, strlen(msg), 0);
      close(clientNum);
      break;
    }
    //if the client is requesting a list of connected clients
    else if(message[0] == '-' && message[1] == 'l')
    {
      int i;
      char list[LINE_MAX] = "Clients Connected: ";
      for(i = 0; i <= numClients; i++)
      {
        //if the client has disconnected, they cannot be contacted
        if(clients[i] == -1 || clients[i] == *clientsocket)
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
    //if the user wants to message a specific client
    else if(message[0] == '-' && message[1] == 'm')
    {
      int i;
      int target = atoi(&message[2]);
      int clientNum = -1;
      for(i = 0; i < numClients; i++)
      {
        if(clients[i] == target)
        {
          clientNum = clients[i];
        }
      }

      printf("Target Client is: %d\n", clientNum);
      if(clientNum < 0)
      {
        printf("Invalid Client Number\n");
        char *error = "Invalid Client Number";
        send(*clientsocket, error, strlen(error), 0);
      }
      send(clientNum, &message[3], strlen(message), 0);
    }
    else
    {
      printf("Message Received: %s\n", message);
    }
    bzero(message, sizeof(message));
  }
  int i;
  //mark that client as inactive
  for(i = 0; i < numClients; i++)
  {
    if(clients[i] == *clientsocket)
    {
      clients[i] = -1;
    }
  }
  close(*clientsocket);
  printf("Connection closed\n");
}
