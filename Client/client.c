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
void handleErrors(void);
void pthreads_thread_id(CRYPTO_THREADID *tid);
void pthreads_locking_callback(int mode, int type, const char *file, int line);
void thread_setup(void);
static pthread_mutex_t *lock_cs;
static long *lock_count;
unsigned char symkey[32];
unsigned char iv[16];

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
    unsigned char encrypted_key[256];
    unsigned char ciphertext[1024];
    unsigned char decryptedtext[1024];
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    OPENSSL_config(NULL);
    RAND_bytes(symkey,32);
    RAND_pseudo_bytes(iv,16);
    EVP_PKEY *pubkey, *privkey;
    FILE* pubf = fopen(pubfilename,"rb");
    //read public key
    pubkey = PEM_read_PUBKEY(pubf,NULL,NULL,NULL);
    FILE* privf = fopen(privfilename,"rb");
    privkey = PEM_read_PrivateKey(privf,NULL,NULL,NULL);
    //encrypt symmetric key
    int encryptedkey_len = rsa_encrypt(symkey, 32, pubkey, encrypted_key);

    /* End initial OpenSSl setup */

    char port[20];
    char message[1024];
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
    //send symmetric key
    printf("\n------------------\nSymKey: %s\nEncKey: %s\n------------------\n", symkey, encrypted_key);
    //send symmetric key
    //send(sockfd, encrypted_key, sizeof(encrypted_key), 0);
    send(sockfd, encrypted_key, strlen(encrypted_key), 0);
    //printf("IV: %s\n", iv);
    send(sockfd, iv, sizeof(iv), 0);

		while(1)
		{
			//send the file name to the server
			printf("Enter a message or type 'q' to quit: ");
      fgets(message, sizeof(message), stdin);
			if(message[0] == 'q' && strlen(message) == 1)
			{
				printf("Closing Connections...\n");
				close(sockfd);
				close(serversocket);
				exit(0);
			}
      //Encrypt message
      unsigned char ciphertext[1024];
      int ciphertext_len = encrypt(message, strlen((char *)message), symkey, iv, ciphertext);
      //printf("ciphertext: %s\n", ciphertext);
      //unsigned char decrypted_key[32];
      //int decryptedkey_len = rsa_decrypt(encrypted_key, encryptedkey_len, privkey, decrypted_key);

      //int decryptedtext_len = decrypt(ciphertext, ciphertext_len, decrypted_key, iv, decryptedtext);
      //printf("Encrypted len: %d\n", ciphertext_len);
      //printf("strlen: %d\n", (int)strlen(ciphertext));


      send(sockfd, ciphertext, ciphertext_len, 0);
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
    char message[1024];
    char decryptedtext[1024];
    if(recv(sockfd, message, sizeof(message), 0) == 0)
    {
      printf("Server has closed the connection\n");
      exit(0);
    }
    printf("\n-----------------\nEncText: %s\nsymkey: %s\nIV: %s\n-----------------\n", message, symkey, iv);
    decrypt(message, strlen(message), symkey, iv, decryptedtext);
    char *newMsg = malloc(strlen(decryptedtext));
    memcpy(newMsg, decryptedtext, strlen(decryptedtext));
    printf("\nReceived: %s\n", newMsg);
    bzero(message, sizeof(message));
    fflush(stdout);
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

int rsa_encrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_encrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
	unsigned char *iv, unsigned char *ciphertext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
	    unsigned char *iv, unsigned char *plaintext){
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    handleErrors();
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}

int rsa_decrypt(unsigned char* in, size_t inlen, EVP_PKEY *key, unsigned char* out){
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  ctx = EVP_PKEY_CTX_new(key,NULL);
  if (!ctx)
    handleErrors();
  if (EVP_PKEY_decrypt_init(ctx) <= 0)
    handleErrors();
  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, NULL, &outlen, in, inlen) <= 0)
    handleErrors();
  if (EVP_PKEY_decrypt(ctx, out, &outlen, in, inlen) <= 0)
    handleErrors();
  return outlen;
}
