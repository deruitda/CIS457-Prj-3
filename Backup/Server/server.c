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
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

void *threadListener(void *args);
void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
void thread_setup(void);
int *clients;
int numClients;
static pthread_mutex_t *lock_cs;
static long *lock_count;
/**************************************
 * Server
 *************************************/

int main(int argc, char **argv)
{
    //first get threads ready
    thread_setup();

    /* Begin initial OpenSSL setup */
    unsigned char *pubfilename = "RSApub.pem";
    unsigned char *privfilename = "RSApriv.pem";
    unsigned char key[32];
    unsigned char iv[16];
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    int decryptedtext_len, ciphertext_len;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    RAND_bytes(key,32);
    RAND_pseudo_bytes(iv,16);
    EVP_PKEY *pubkey, *privkey;
    FILE* pubf = fopen(pubfilename,"rb");
    pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
    /* End initial OpenSSl setup */

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

//////////////////////////////////
//Get program to work with threads
/////////////////////////////////
void thread_setup(void)
{
    int i;

    lock_cs = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
    lock_count = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(long));
    for (i = 0; i < CRYPTO_num_locks(); i++) {
        lock_count[i] = 0;
        pthread_mutex_init(&(lock_cs[i]), NULL);
    }

    CRYPTO_THREADID_set_callback(pthreads_thread_id);
    CRYPTO_set_locking_callback(pthreads_locking_callback);
}

void pthreads_thread_id(CRYPTO_THREADID *tid)
{
    CRYPTO_THREADID_set_numeric(tid, (unsigned long)pthread_self());
}

void pthreads_locking_callback(int mode, int type, const char *file, int line)
{
# ifdef undef
    BIO_printf(bio_err, "thread=%4d mode=%s lock=%s %s:%d\n",
               CRYPTO_thread_id(),
               (mode & CRYPTO_LOCK) ? "l" : "u",
               (type & CRYPTO_READ) ? "r" : "w", file, line);
# endif
/*-
    if (CRYPTO_LOCK_SSL_CERT == type)
            BIO_printf(bio_err,"(t,m,f,l) %ld %d %s %d\n",
                       CRYPTO_thread_id(),
                       mode,file,line);
*/
    if (mode & CRYPTO_LOCK) {
        pthread_mutex_lock(&(lock_cs[type]));
        lock_count[type]++;
    } else {
        pthread_mutex_unlock(&(lock_cs[type]));
    }
}
