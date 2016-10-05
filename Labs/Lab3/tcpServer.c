//Danny DeRuiter

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

void *threadListener(void *arg);
void *threadSender(void *arg);

int clientsocket;
int sockfd;
struct sockaddr_in clientaddr, serveraddr;
int main(int argc, char **argv)
{
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        int port;
        int len;
		char dummy[10];
		
        //get the port
        printf("Enter a port: ");
        scanf("%d", &port);
        fgets(dummy, sizeof(dummy), stdin);
        //server is specifying its own address
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_port = htons(port);
        serveraddr.sin_addr.s_addr = INADDR_ANY; //a catchall saying use any IP addr this computer has

        bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

        listen(sockfd, 10);

        len = sizeof(clientaddr);

		clientsocket = accept(sockfd, (struct sockaddr *) &clientaddr, &len);
		if (clientsocket < 0) {
			printf("Error accepting connection!\n");
			return 1;
		} 
		
        pthread_t listener;
        pthread_t sender;
        //start lisening thread
        pthread_create(&listener, NULL, threadListener, "");
        
		char line[5000];
		char quit[5] = "quit";
		memset(line, 0, 5000);
		printf("Type a message and hit return to send it: \n");
		while(fgets(line, 5000, stdin) != NULL)
		{
			printf("Compare: %d", strcmp(line, quit));
            if(strcmp(line, "quit") == 0)
            {
                    printf("quitting...\n");
					close(clientsocket);
					close(sockfd);
					char msg[30] = "Connection has been terminated\n";
					send(clientsocket, msg, sizeof(msg), 0);
                    break;
            }
            send(clientsocket, line, strlen(line), 0);
        }
		pthread_exit(NULL);
        return 0;
}

void *threadListener(void *arg)
{
        int len = sizeof(clientaddr);
        while(1)
        {
                if(clientsocket != -1)
                {
                        char line[5000];
                        recv(clientsocket, line, sizeof(line), 0);
                        printf("Client: %s\n", line);
                }
        }
}

