/* Client code */
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

#define PORT_NUMBER     1221
#define SERVER_ADDRESS  "127.0.0.1"
#define FILENAME        "hi.txt"

int main(int argc, char **argv)
{
        int client_socket;
        ssize_t len;
        struct sockaddr_in remote_addr;
        char buffer[BUFSIZ];
        int file_size;
        FILE *received_file;
        int remain_data = 0;

        /* Zeroing remote_addr struct */
        memset(&remote_addr, 0, sizeof(remote_addr));

        /* Construct remote_addr struct */
        remote_addr.sin_family = AF_INET;
        inet_pton(AF_INET, SERVER_ADDRESS, &(remote_addr.sin_addr));
        remote_addr.sin_port = htons(PORT_NUMBER);

        /* Create client socket */
        client_socket = socket(AF_INET, SOCK_STREAM, 0);
        if (client_socket == -1)
        {
                fprintf(stderr, "Error creating socket --> %s\n", strerror(errno));

                exit(EXIT_FAILURE);
        }

        /* Connect to the server */
        if (connect(client_socket, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr)) == -1)
        {
                fprintf(stderr, "Error on connect --> %s\n", strerror(errno));

                exit(EXIT_FAILURE);
        }

		//Read Picture Size
		printf("Reading Picture Size\n");
		int size;
		read(client_socket, &size, sizeof(int));
		
		//Read Picture Byte Array
		printf("Reading Picture Byte Array\n");
		char p_array[size];
		read(client_socket, p_array, size);
		
		//Convert it Back into Picture
		printf("Converting Byte Array to Picture\n");
		FILE *image;
		image = fopen(FILENAME, "w");
		fwrite(p_array, 1, sizeof(p_array), image);
		fclose(image);

        fclose(received_file);

        close(client_socket);

        return 0;
}