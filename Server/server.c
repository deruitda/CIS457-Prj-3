//Danny DeRuiter

#include <stdio.h>
#include <sys/types.h>
#include <sys/ipc.h>
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

/**************************************
 * Server
 *************************************/

int main(int argc, char **argv)
{
    int *clients;
    int port, clientsocket, numClients, pid, shmID;

    //set up shared mem segment
    key_t key = 1221;
    shmID = shmget(key, sizeof(int)*15, IPC_CREAT);
    clients = (int *)shmat(shmID,  0, 0);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		char message[LINE_MAX];
		FILE *fp;

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
		while(1)
		{
			clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, &len);
			if(clientsocket == -1)
			{
				fprintf(stderr, "Could not accept client connection...\n");
				exit(1);
			}
      clients[numClients] = clientsocket;
      numClients++;
			printf("Connection established...\n");
      printf("List of clients: ");
      int j;
      for(j = 0; j <= numClients; j++)
      {
        printf("%d, ", clients[j]);
      }
      printf("\n");
			//create a new child process to handle the new connection
			if((pid = fork()) < 0)
			{
				fprintf(stderr, "Error creating child process.\n");
				exit(1);
			}

			//if it's the child process
			if(pid == 0)
			{
				while(recv(clientsocket, message, sizeof(message), 0) > 0)
				{
          if(message[0] == '-' && message[1] == 'b')
          {
            printf("Broadcasting message to all clients...\n");
            int i;
            for(i = 0; i <= numClients; i++)
            {
              send(clients[i], message, strlen(message), 0);
              printf("Send to client: %d\n", clients[i]);
            }
          }
           else if(message[0] == '-' && message[1] == 'l')
          {
            int i;
            char list[LINE_MAX] = "Client numbers: ";
            for(i = 0; i <= numClients; i++)
            {
              char num[5];
              sprintf(num, "%d", clients[i]);
              strcat(list, num);
              strcat(list, ", ");
            }
            printf("List: %s\n", list);
            send(clientsocket, list, strlen(list), 0);
            printf("Sent list to client\n");
          }
          else
          {
            printf("Message Received: %s\n", message);
            bzero(message, sizeof(message));
          }
        }
				//when the loop stops the client has closed the connection
				close(clientsocket);
				printf("Connection closed\n");
			}

	}
	return 0;
}
