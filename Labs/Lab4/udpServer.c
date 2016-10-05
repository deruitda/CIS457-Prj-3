#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0)
    {
      printf("Error creating socket\n");
      return 1;
    }

    struct sockaddr_in serveraddr, clientaddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_port = htons(1221);
    serveraddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    while(1)
    {
        int len = sizeof(struct sockaddr_in);
        char line[1000];
        int n = recvfrom(sockfd, line, 1000, 0, (struct sockaddr*)&serveraddr, &len);
        printf("Received: %s\n", line);
    }

    printf("Enter a line: ");
    char line[1000];
    fgets(line, 1000, stdin);
    sendto(sockfd, line, strlen(line), 0, (struct sockaddr*)&serveraddr, sizeof(struct sockaddr_in));
    return 0;

}