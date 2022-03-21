#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <yaml.h>

#include "parse.h"

// Wolfcrypt
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

// Socket
#define LISTENQ 1024
#define PORT 50000
#define ECC_KEY_LEN 32

#define MAX_MSG_LEN 4096

// YAML
#define YAML_FILE "tcp.yaml"
#define QUERY_PARITY_OR_TCP_BYTE 1
#define QUERY_IP_OR_DEVICE_BYTE 16
#define QUERY_PORT_OR_BAUD_BYTE 4
#define QUERY_PROTOID_OR_DATABIT_BYTE 2
#define QUERY_SERVERID_OR_STOPBIT_BYTE 1	// 2
#define QUERY_FC_BYTE 1 					// 2
#define QUERY_STARTREGADDR_BYTE 2
#define QUERY_COMMAND_BYTE 2
#define QUERY_DURATION_BYTE 3 				// 1
#define QUERY_RESERVED_BYTE 0
#define QUERY_TOTAL_LEN 32 // should equal to sum of all query bytes

#define QUERY_TCP 0
#define QUERY_RTU 1

enum
{
    INIT = 0, // initialization phase
    REG,  // registration phase
    AUTH, // authentication phase
    COMM  // communication phase
};

typedef struct {
    int infd;
	int listenfd; // listenfd
	struct sockaddr_in clientaddr[1];
	RNG rng[1]; // wolfssl
	Sha256 sha[1]; // wolfssl
    uint8_t psk[ECC_KEY_LEN]; // pre-shared key
	uint8_t aid[ECC_KEY_LEN]; // alias id
    char buf[MAX_MSG_LEN];
    uint8_t session_key[ECC_KEY_LEN];
} session_info_t;

double tvgetf()
{
    struct timespec ts;
    double sec;

    clock_gettime(CLOCK_REALTIME, &ts);
    sec = ts.tv_nsec;
    sec /= 1e9;
    sec += ts.tv_sec;

    return sec;
}

void print_hex(const uint8_t *s, int len, int flag)
{
    if (!flag) return;
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

void do_xor(uint8_t *out, const uint8_t *lhs, const uint8_t *rhs, int len)
{
    for(int i=0; i<len; ++i) {
        /* Accept a connection from client */
        out[i] = lhs[i] ^ rhs[i];
    }
}

static int open_listenfd(int port)
{
    int listenfd, optval = 1;

    /* socket */
    if ((listenfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        return -1;
    }
    if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval, sizeof(int)) < 0) {
    	return -1;
    }

    struct sockaddr_in serveraddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons((unsigned short) port),
        .sin_zero = {0},
    };
    
    if (bind(listenfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr)) < 0) {
	    perror("bind");
        return -1;
    }

    if (listen(listenfd, LISTENQ) < 0) {
        return -1;
    }

    return listenfd;
}

/* Registration Phase */
int do_registration(int infd, uint8_t *psk, uint8_t *aid, RNG *rng, Sha256 *sha)
{
    int ret = 0;

    /* Assume authentication server is responsible for the process below (AS sends aid and psk to server)*/
    uint8_t sid[ECC_KEY_LEN] = {};
    ret = wc_RNG_GenerateBlock(rng, sid, ECC_KEY_LEN);
    if (ret != 0) {
        printf("sid gen failed: %d\n", ret);
	return -1;
    }

    wc_Sha256Update(sha, sid, ECC_KEY_LEN);
    wc_Sha256Final(sha, aid);
    
    //print_hex(aid, ECC_KEY_LEN, 1);

    for (int i=0; i<ECC_KEY_LEN; i++) {
        psk[i] = 255; // Assume psk is set 
    }
    return ret;
}

/* Authentication Phase */
int do_authentication(int infd, uint8_t *session_key, const uint8_t *psk, const uint8_t *aid, RNG *rng, Sha256 *sha)
{
    uint8_t buf[MAX_MSG_LEN] = {};
    uint8_t concator[ECC_KEY_LEN*3] = {};
    uint8_t hash[ECC_KEY_LEN] = {};
    
    int ret = 0;
    // Wait for client TODO: Put this outside
    ret = read(infd, buf, ECC_KEY_LEN*4);
    if (ret != ECC_KEY_LEN*4) {
		perror("do_authentication read");
	    return -1;
    }
    uint8_t client_M[ECC_KEY_LEN] = {};
    uint8_t client_aid_x[ECC_KEY_LEN] = {};
    uint8_t client_aid_y[ECC_KEY_LEN] = {};
    uint8_t client_f[ECC_KEY_LEN] = {};
    memcpy(client_M, buf, ECC_KEY_LEN);
    memcpy(client_aid_x, buf+ECC_KEY_LEN, ECC_KEY_LEN);
    memcpy(client_aid_y, buf+ECC_KEY_LEN*2, ECC_KEY_LEN);
    memcpy(client_f, buf+ECC_KEY_LEN*3, ECC_KEY_LEN);
    
    uint8_t client_sid[ECC_KEY_LEN] = {};

    do_xor(client_sid, psk, client_f, sizeof(client_sid));

    //print_hex(client_sid, sizeof(client_sid), 1);

    // retrieve client aid
    uint8_t client_aid[ECC_KEY_LEN] = {};
    wc_Sha256Update(sha, client_sid, ECC_KEY_LEN);
    wc_Sha256Final(sha, client_aid);
    // Ax_re = client_aid_x ^ client_aid
    // Ay_re = client_aid_y ^ client_aid
    uint8_t client_pubkey_point[ECC_KEY_LEN*2] = {};

    do_xor(client_pubkey_point, client_aid_x, client_aid, ECC_KEY_LEN);
    do_xor(client_pubkey_point + ECC_KEY_LEN, client_aid_y, client_aid, ECC_KEY_LEN);

    //print_hex(client_pubkey_point, ECC_KEY_LEN, 1);

    //print_hex(client_pubkey_point + ECC_KEY_LEN, ECC_KEY_LEN, 1);


    // Check if h(client_aid||Ax_re||Ay_re) equals to client_M
    memcpy(concator, client_aid, sizeof(client_aid));
    memcpy(concator + sizeof(client_aid), client_pubkey_point, ECC_KEY_LEN);
    memcpy(concator + sizeof(client_aid) + ECC_KEY_LEN, client_pubkey_point + ECC_KEY_LEN, ECC_KEY_LEN);
    wc_Sha256Update(sha, concator, ECC_KEY_LEN*3);
    wc_Sha256Final(sha, hash);


    for (int i=0; i<sizeof(hash); ++i) {
        if (hash[i] != client_M[i]) {
	    return -1;
	}
    }
    
    // Generate ecc priv/pub key pair, then export public into raw format
    ecc_key key;
    uint8_t pubkey_point[ECC_KEY_LEN*2] = {};
    uint32_t xLen = ECC_KEY_LEN, yLen = ECC_KEY_LEN;

    wc_ecc_init(&key);
    wc_ecc_make_key(rng, ECC_KEY_LEN, &key);
    wc_ecc_export_public_raw(&key, pubkey_point, &xLen, pubkey_point + ECC_KEY_LEN, &yLen);

    //print_hex(pubkey_point, xLen, 1);

    //print_hex(pubkey_point + ECC_KEY_LEN, yLen, 1);

    // server_f = server_aid ^ hash(Ax_re||By)
    uint8_t f[ECC_KEY_LEN] = {};

    memcpy(concator, client_pubkey_point, ECC_KEY_LEN);
    memcpy(concator + ECC_KEY_LEN, pubkey_point + ECC_KEY_LEN, ECC_KEY_LEN);
    wc_Sha256Update(sha, concator, ECC_KEY_LEN*2);
    wc_Sha256Final(sha, hash);

    do_xor(f, aid, hash, sizeof(f));

    //print_hex(f, sizeof(f), 1);

    // AID_jx = Bx ^ client_aid
    // AID_jy = By ^ client_aid
    uint8_t aid_x[ECC_KEY_LEN], aid_y[ECC_KEY_LEN];

    do_xor(aid_x, pubkey_point, client_aid, sizeof(aid_x));
    do_xor(aid_y, pubkey_point + ECC_KEY_LEN, client_aid, sizeof(aid_y));

    //print_hex(aid_x, sizeof(aid_x), 1);

    //print_hex(aid_y, sizeof(aid_y), 1);

    // server_M = hash(server_sid||Bx||By)
    uint8_t M[ECC_KEY_LEN];

    memcpy(concator, aid, ECC_KEY_LEN);
    memcpy(concator + ECC_KEY_LEN, pubkey_point, xLen);
    memcpy(concator + ECC_KEY_LEN + xLen, pubkey_point + ECC_KEY_LEN, yLen);
    wc_Sha256Update(sha, concator, ECC_KEY_LEN + xLen + yLen);
    wc_Sha256Final(sha, M);

    //print_hex(M, sizeof(M), 1);
    
    // Send (server_M, server_aid_x, server_aid_y, server_f) to client
    memcpy(buf, M, ECC_KEY_LEN);
    memcpy(buf + ECC_KEY_LEN, aid_x, ECC_KEY_LEN);
    memcpy(buf + ECC_KEY_LEN*2, aid_y, ECC_KEY_LEN);
    memcpy(buf + ECC_KEY_LEN*3, f, ECC_KEY_LEN);
    ret = write(infd, buf, ECC_KEY_LEN*4);
    if (ret < ECC_KEY_LEN*4) {
        printf("write may failed\n");
	return -1;
    }

    //create client2server
    ecc_key client_pubkey;
    wc_ecc_init(&client_pubkey);
    client_pubkey.rng = rng;
    key.rng = rng;
    ret = wc_ecc_import_unsigned(&client_pubkey, client_pubkey_point, client_pubkey_point + ECC_KEY_LEN, NULL, 7);
    if (ret != MP_OKAY) {
        printf("wc_ecc_import_raw failed %d\n", ret);
	return -1;
    }
    //uint8_t SKs[ECC_KEY_LEN] = {};
    word32 secret_size = ECC_KEY_LEN;
    ret = wc_ecc_shared_secret(&key, &client_pubkey, session_key, &secret_size);
    if (ret != 0) {
        printf("shared_secret failed %d\n", ret);
	return -1;
    }
    //print_hex(session_key, ECC_KEY_LEN, 1);
    return ret;
}

int do_communication(int infd, query_t *query)
{
    int ret;
    while (1) {
        ret = read(infd, buf, sizeof(buf));
	if (ret <= 0) {
	    printf("read may failed\n");
	    break;
	} else {
	    write(infd, buf, ret);
	}
    }
    printf("comm finish, exit\n");
}

int config_ktls(int infd, const uint8_t *session_key)
{
    int ret = 0;
    time_t t;
    unsigned int rand_hi, rand_lo;
    srand((unsigned int)time(&t));

    // init rand
    rand_hi = rand();
    rand_lo = rand();

    // manipulate seqNum
    unsigned long seq;
    memset(&seq, 0, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
    
    // manipulate iv
    unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    memset(iv, 0, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    //iv[TLS_CIPHER_AES_GCM_256_IV_SIZE-1] = 0x01;


    struct tls12_crypto_info_aes_gcm_256 crypto_info;

    ret = setsockopt(infd, SOL_TCP, TCP_ULP, "tls", sizeof("tls"));
    if (ret < 0) {
		perror("config_ktls setsockopt");
	    return -1;
    }
    crypto_info.info.version = TLS_1_2_VERSION;
    crypto_info.info.cipher_type = TLS_CIPHER_AES_GCM_256;
    memcpy(crypto_info.key, session_key, ECC_KEY_LEN);
    memcpy(crypto_info.iv, iv, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    memcpy(crypto_info.rec_seq, &seq, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);
    memcpy(crypto_info.salt, iv, TLS_CIPHER_AES_GCM_256_SALT_SIZE);

    //Set TX/RX
    if (setsockopt(infd, SOL_TLS, TLS_TX, &crypto_info, sizeof(crypto_info)) < 0) {
        printf("setsockopt TX failed\n");
	return -1;
    }

    if (setsockopt(infd, SOL_TLS, TLS_RX, &crypto_info, sizeof(crypto_info)) < 0) {
        printf("setsockopt RX failed\n");
	return -1;
    }

    return 0;
}

void *do_handle_client(void *arg)
{
    session_info_t *session_info = arg;

	int infd = session_info->infd;
	uint8_t *psk = session_info->psk;
	uint8_t *aid = session_info->aid;
	RNG *rng = session_info->rng;
	Sha256 *sha = session_info->sha;
	int ret;
    
    /* Authentication */
    double t1 = tvgetf();
    ret = do_authentication(infd, session_info->session_key, psk, aid, rng, sha);
    double t2 = tvgetf();
    if (ret != 0) {
        printf("do_auth failed\n");
	    close(infd);
		return NULL;
    }
    printf("Handshake complete! %f msec.\n", (t2-t1)*1000);
    free(arg);
    return NULL;


    /* Configure Kernel TLS */
    if (config_ktls(infd, session_info->session_key) < 0) {
        printf("configure ktls failed\n");
		close(infd);
		return NULL;
    }
   
    /* Communication */
    do_communication(infd, state.qlist);

    close(infd);
    return NULL;
}


int main()
{
    int ret;

	/* Open Socket */
    int listenfd = open_listenfd(PORT);

    /* Initialization */
    RNG rng[1];
    Sha256 sha[1];
    if (wc_InitRng(rng) != 0) {
	    return -1;
    }
    if (wc_InitSha256(sha) != 0) {
	    return -1;
    }

    /* Registration Phase */
    /* Connect and register to authentication server */
	printf("Registration Phase...\n");
    
	uint8_t psk[ECC_KEY_LEN] = {};
    uint8_t aid[ECC_KEY_LEN] = {};

    ret = do_registration(listenfd, psk, aid, rng, sha);
    if (ret != 0) {
        printf("registration phase failed\n");
	    return -1;
    }

    
	printf("Wait for connection...\n");
    /* Accept connections from client */
    struct sockaddr_in clientaddr;
    socklen_t inlen = sizeof(clientaddr);
	pthread_t thread;
    
	while (1) {
	    /* Allocate memory for each session */
	    session_info_t *session_info = malloc(sizeof(session_info_t));
        
	    session_info->infd = accept(listenfd, (struct sockaddr *) &clientaddr, &inlen);

	    session_info->listenfd = listenfd;
	    memcpy(session_info->psk, psk, ECC_KEY_LEN);
	    memcpy(session_info->aid, aid, ECC_KEY_LEN);
	    memcpy(session_info->rng, rng, sizeof(RNG));
	    memcpy(session_info->sha, sha, sizeof(Sha256));
	    memcpy(session_info->clientaddr, &clientaddr, sizeof(struct sockaddr));

	    if (session_info->infd < 0) {
	        printf("accept error\n");
	        return -1;
	    }
	    pthread_create(&thread, NULL, do_handle_client, session_info);
        }

    return 0;
}

