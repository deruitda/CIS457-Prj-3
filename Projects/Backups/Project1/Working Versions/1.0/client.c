//Danny DeRuiter

#include <stdio.h>
#include <sys/socket.h> //used for multiple types of connections
#include <netinet/in.h> //used for common internet protocols
#include <string.h>
#include <limits.h>

/**************************************
 * Client
 *************************************/
int main(int argc, char **argv)
{
        char port[20];
        char ip_address[20];
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
        FILE *fp;
		char filename[20];
		memset(filename, 0, sizeof(filename));
		printf("Enter the file you want to receive: ");
		scanf("%s", filename);
		send(sockfd, filename, strlen(filename), 0);
		fp = fopen(filename, "ab");
		//Read Picture Size
		printf("Reading Picture Size\n");
		int size;
		read(sockfd, &size, sizeof(int));
		
		//Read Picture Byte Array
		printf("Reading Picture Byte Array\n");
		char p_array[size];
		read(sockfd, p_array, size);
		
		//Convert it Back into Picture
		printf("Converting Byte Array to Picture\n");
		FILE *image;
		image = fopen(FILENAME, "w");
		fwrite(p_array, 1, sizeof(p_array), image);
		fclose(image);
		
		close(sockfd);
        close(serversocket);
        return 0;
}
