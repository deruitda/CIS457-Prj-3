//Danny DeRuiter

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
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
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        int port;
        int clientsocket;
		char filename[20];
		FILE *fp;
		int pid;
		
        //get the port
        printf("Enter a port: ");
        scanf("%d", &port);
        //server is specifying its own address
        struct sockaddr_in serveraddr, clientaddr;
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_port = htons(port);
        serveraddr.sin_addr.s_addr = INADDR_ANY; //a catchall saying use any IP addr this computer has

        //Bind: Tie addr to socket saying when something is to be done with socket, use this addr
        bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

        //listens to specified socket
        //10 is number of turns until we stop listening
        listen(sockfd, 10);

        int len = sizeof(clientaddr);
		
		while(1)
		{	
			clientsocket = accept(sockfd, (struct sockaddr*)&clientaddr, &len);
			if(clientsocket == -1)
			{
				fprintf(stderr, "Could not accept client connection...\n");
				exit(1);
			}
			printf("Connection established...\n");
			
			if((pid = fork()) < 0)
			{
				fprintf(stderr, "Error creating child process.\n");
				exit(1);
			}
	
			if(pid == 0)
			{
				//get file size
				memset(filename, 0, 20);
				while(recv(clientsocket, filename, sizeof(filename), 0) > 0)
				{
					printf("Filename: %s\n", filename);
					if((fp = fopen(filename, "r")) == NULL)
					{
						printf("File not found\n");
						//need to notify client that the file was not found
						break;
					}
					printf("File %s found\n", filename);
					int size;
					fseek(fp, 0, SEEK_END);
					size = ftell(fp);
					fseek(fp, 0, SEEK_SET);
					printf("File size: %i\n", size);
					
					//send file size
					printf("sending file size...\n");
					write(clientsocket, &size, sizeof(size));
					
					fflush(stdout);
					printf("Sending file contents...\n");
					//Send file as array of bytes
					char buff[size];
					while(!feof(fp)) 
					{
						fread(buff, 1, sizeof(buff), fp);
						write(clientsocket, buff, sizeof(buff));
						bzero(buff, sizeof(buff));
					}
					fclose(fp);
					filename[0] = '\0';
				}
				//when we exit the loop, we know the client has closed the connection
				close(clientsocket);
				printf("Connection closed\n");
			}
	
	}
	return 0;
}
