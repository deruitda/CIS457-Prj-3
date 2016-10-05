/* Server code */
/* TODO : Modify to meet your need */
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

#define PORT_NUMBER     1221
#define SERVER_ADDRESS  "127.0.0.1"
#define FILE_TO_SEND    "hello.txt"

int main(int argc, char **argv)
{
        int server_socket;
        int peer_socket;
        socklen_t       sock_len;
        ssize_t len;
        struct sockaddr_in      server_addr;
        struct sockaddr_in      peer_addr;
        //int fd;
        int sent_bytes = 0;
        char file_size[256];
        struct stat file_stat;
        int offset;
        int remain_data;

        /* Create server socket */
        server_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket == -1)
        {
                fprintf(stderr, "Error creating socket --> %s", strerror(errno));

                exit(EXIT_FAILURE);
        }

        /* Zeroing server_addr struct */
        memset(&server_addr, 0, sizeof(server_addr));
        /* Construct server_addr struct */
        server_addr.sin_family = AF_INET;
        inet_pton(AF_INET, SERVER_ADDRESS, &(server_addr.sin_addr));
        server_addr.sin_port = htons(PORT_NUMBER);

        /* Bind */
        if ((bind(server_socket, (struct sockaddr *)&server_addr, sizeof(struct sockaddr))) == -1)
        {
                fprintf(stderr, "Error on bind --> %s\n", strerror(errno));

                exit(EXIT_FAILURE);
        }

        /* Listening to incoming connections */
        if ((listen(server_socket, 5)) == -1)
        {
                fprintf(stderr, "Error on listen --> %s\n", strerror(errno));

                exit(EXIT_FAILURE);
        }

        sock_len = sizeof(struct sockaddr_in);
        /* Accepting incoming peers */
        peer_socket = accept(server_socket, (struct sockaddr *)&peer_addr, &sock_len);
        if (peer_socket == -1)
        {
                fprintf(stderr, "Error on accept --> %s", strerror(errno));

                exit(EXIT_FAILURE);
        }
        fprintf(stdout, "Accept peer --> %s\n", inet_ntoa(peer_addr.sin_addr));

		//Get Picture Size
		printf("Getting Picture Size\n");
		FILE *fp;
		if((fp = fopen(FILE_TO_SEND, "r")) == NULL)
		{
			printf("File not found\n");
		}
		
		int size;
		fseek(fp, 0, SEEK_END);
		size = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		
		//Send Picture Size
		printf("Sending Picture Size\n");
		write(peer_socket, &size, sizeof(size));
		
		//Send Picture as Byte Array
		printf("Sending Picture as Byte Array\n");
		char send_buffer[size];
		while(!feof(fp)) {
			fread(send_buffer, 1, sizeof(send_buffer), fp);
			write(peer_socket, send_buffer, sizeof(send_buffer));
			bzero(send_buffer, sizeof(send_buffer));
		}

        close(peer_socket);
        close(server_socket);

        return 0;
}