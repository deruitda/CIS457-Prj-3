//Danny DeRuiter

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <pthread.h>
#include <openssl/conf.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

void *threadListener(void *arg);
void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
void thread_setup(void);
static pthread_mutex_t *lock_cs;
static long *lock_count;


struct sockaddr_in serveraddr;
int sockfd, serversocket;
/**************************************
 * Client
 *************************************/
int main(int argc, char **argv)
{
    thread_setup();

    /* Begin initial OpenSSL setup */
    unsigned char *pubfilename = "RSApub.pem";
    unsigned char *privfilename = "RSApriv.pem";
    unsigned char symkey[32];
    unsigned char iv[16];
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    int decryptedtext_len, ciphertext_len;
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    RAND_bytes(symkey,32);
    RAND_pseudo_bytes(iv,16);
    EVP_PKEY *pubkey, *privkey;
    FILE* pubf = fopen(pubfilename,"rb");
    pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
    /* End initial OpenSSl setup */

    char port[20];
    char message[LINE_MAX];
    char ip_address[20];
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
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
    serveraddr.sin_family = AF_INET; //what time of socket it is
    serveraddr.sin_port = htons((atoi(port))); //this is so the server knows where to return data
    serveraddr.sin_addr.s_addr = inet_addr(ip_address);

    int e = connect(sockfd, (struct sockaddr*)&serveraddr, sizeof(serveraddr));

    pthread_t listener;
    pthread_create(&listener, NULL, threadListener, "");

    if(e < 0)
    {
      printf("There was an error with connecting\n");
      return 1;
    }

    int len = sizeof(serveraddr);
    serversocket = accept(sockfd, (struct sockaddr*)&serveraddr, &len);
    printf("Connected to chat server. Type '-h' for help.\n");
		while(1)
		{
			//send the file name to the server
			printf("Enter a message or type 'q' to quit: ");
			scanf("%s", message);
			if(message[0] == 'q' && strlen(message) == 1)
			{
				printf("Closing Connections...\n");
				close(sockfd);
				close(serversocket);
				exit(0);
			}
			send(sockfd, message, strlen(message), 0);
      bzero(message, sizeof(message));
      fflush(stdout);
		}

		close(sockfd);
    close(serversocket);
    return 0;
}

void *threadListener(void *arg)
{
  int len = sizeof(serveraddr);
  while(1)
  {
    char message[LINE_MAX];
    if(recv(sockfd, message, sizeof(message), 0) == 0)
    {
      printf("Server has closed the connection\n");
      exit(0);
    }

    printf("\nReceived: %s\n", message);
    bzero(message, sizeof(message));
  }
}

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
