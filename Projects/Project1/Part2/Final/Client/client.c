//Danny DeRuiter

#include <stdio.h>
#include <sys/socket.h> 
#include <netinet/in.h> 
#include <string.h>
#include <limits.h>
#include <stdlib.h>

/**************************************
 * Client
 *************************************/
int main(int argc, char **argv)
{
        char port[20];
        char ip_address[20];
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
		FILE *fp;
        char recvBuff[256];
		char filename[20];
		memset(recvBuff, '0', sizeof(recvBuff));
		memset(filename, 0, sizeof(filename));
		
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
        struct sockaddr_in serveraddr;
        serveraddr.sin_family = AF_INET; //what time of socket it is
        serveraddr.sin_port = htons((atoi(port))); //this is so the server knows where to return data
        serveraddr.sin_addr.s_addr = inet_addr(ip_address);

        int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

        if(e < 0)
        {
                printf("There was an error with connecting\n");
                return 1;
        }

        int len = sizeof(serveraddr);
        int serversocket = accept(sockfd, (struct sockaddr*)&serveraddr, &len);
		
		while(1)
		{	
			//send the file name to the server
			printf("Enter the file you want to receive (type q to quit): ");
			scanf("%s", filename);
			if(filename[0] == 'q' && strlen(filename) == 1)
			{
				printf("Closing Connections...\n");
				close(sockfd);
				close(serversocket);
				exit(0);
			}
			send(sockfd, filename, strlen(filename), 0);
			
			//create the file to write to
			fp = fopen(filename, "ab");
	
			//get file size from server
			int size;
			read(sockfd, &size, sizeof(size));
			printf("File size received: %i\n", size);
			
			//read the array of bytes from the server
			char bytes[size];
			memset(bytes, 0, sizeof(bytes));
			read(sockfd, bytes, size);
			
			//convert bytes to file
			printf("Converting bytes to file...\n");
			fp = fopen(filename, "w");
			fwrite(bytes, 1, sizeof(bytes), fp);
			fclose(fp);
			
			printf("File transfer complete\n");
		}
		
		close(sockfd);
        close(serversocket);
        return 0;
}
