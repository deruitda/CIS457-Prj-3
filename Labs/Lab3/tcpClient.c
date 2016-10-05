//Danny DeRuiter

#include <stdio.h>
#include <sys/socket.h> //used for multiple types of connections
#include <netinet/in.h> //used for common internet protocols
#include <string.h>
#include <limits.h>
#include <pthread.h>
/**************************************
 * Client
 *************************************/
void *threadListener(void *arg);
void *threadSender(void *arg);
struct sockaddr_in serveraddr;
int sockfd;
int serversocket;
int main(int argc, char **argv)
{
        char port[20];
        char ip_address[20];
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        //get the port first
        printf("Enter a port: \n");
        fgets(port, LINE_MAX, stdin);

        //get the IP address
        printf("Enter an IP address: \n");
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

        if(e < 0)
        {
                printf("There was an error with connecting\n");
                return 1;
        }


        pthread_t listener;
        pthread_t sender;
			
        pthread_create(&listener, NULL, threadListener, "");
		
		char dummy[10];
        fgets(dummy, sizeof(dummy), stdin);
        char line[5000];
		memset(line, 0, 5000);
		printf("Type a message and hit return to send it: \n");
        while(fgets(line, sizeof(line), stdin) != NULL)
        {
                if(strcmp(line, "quit") == 0)
                {
                        printf("quitting...\n");
						char msg[30] = "Connection has been terminated";
						send(sockfd, msg, strlen(msg), 0);
                        break;
                }
                send(sockfd, line, strlen(line), 0);
        }
		close(sockfd);
		pthread_exit(NULL);
        return 0;
}

void *threadListener(void *arg)
{
        int len = sizeof(serveraddr);
        printf("Listening for connections...\n");
        while(1)
        {
            char line[5000];
			memset(line, 0, 5000);
            recv(sockfd, line, sizeof(line), 0);
            printf("Server: %s\n", line);
        }
}

