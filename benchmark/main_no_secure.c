#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <time.h>
#include <linux/tls.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <pthread.h>

// Wolfcrypt
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

#define PORT 12345
#define HOST "127.0.0.1"
#define MAX_MSG_LEN 4096
#define ECC_KEY_LEN 32

int outn = 0;
int inn = 0;
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

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

void do_xor(uint8_t *out, const uint8_t *lhs, const uint8_t *rhs, int len)
{
    for (int i=0; i<len; ++i) {
        out[i] = lhs[i] ^ rhs[i];
    }
}

void print_hex(const uint8_t *s, int len)
{
    for (int i=0; i<len; ++i) {
        printf("%02x", s[i]);
    }
    printf("\n");
}

int do_registration(int sockfd, uint8_t *aid, uint8_t *f, RNG *rng, Sha256 *sha)
{
    /* Assume authentication server is responsible for the process below (assign aid and f for client) */
    // Make sid
    uint8_t sid[ECC_KEY_LEN] = {};
    if (wc_RNG_GenerateBlock(rng, sid, ECC_KEY_LEN) != 0) {
        printf("sid generate failed\n");
	return -1;
    }

    wc_Sha256Update(sha, sid, ECC_KEY_LEN);
    wc_Sha256Final(sha, aid);

    // Make f = psk ^ sid, which every bits of psk is "1" for now
    uint8_t psk[ECC_KEY_LEN] = {};
    for (int i=0; i<ECC_KEY_LEN; i++) {
        psk[i] = 255;
	f[i] = psk[i] ^ sid[i];
    }
    return 0;
}

int do_authentication(int sockfd, uint8_t *SK, uint8_t *aid, uint8_t *f, RNG *rng, Sha256 *sha)
{   
    //print_hex(aid, ECC_KEY_LEN);
    uint8_t concator[ECC_KEY_LEN*3] = {};
    uint8_t hash[ECC_KEY_LEN] = {};
    int ret;

    ecc_key key;
    uint8_t pubkey_point[ECC_KEY_LEN*2] = {};
    uint32_t xLen = ECC_KEY_LEN, yLen = ECC_KEY_LEN;
    wc_ecc_init(&key);
    wc_ecc_make_key(rng, ECC_KEY_LEN, &key);
    wc_ecc_export_public_raw(&key, pubkey_point, &xLen, pubkey_point + ECC_KEY_LEN, &yLen);
   
    //print_hex(pubkey_point, xLen);
    //print_hex(pubkey_point + ECC_KEY_LEN, yLen);
    // AID_ix = Ax ^ SID_i
    // AID_iy = Ay ^ SID_i
    uint8_t aid_x[ECC_KEY_LEN], aid_y[ECC_KEY_LEN];
    do_xor(aid_x, pubkey_point, aid, sizeof(aid_x));
    do_xor(aid_y, pubkey_point + ECC_KEY_LEN, aid, sizeof(aid_y));
    
    //print_hex(aid_x, sizeof(aid_x));
    //print_hex(aid_y, sizeof(aid_y));
   
    // M_i = hash(AID_i||Ax||Ay)
    byte M[ECC_KEY_LEN];
    memcpy(concator, aid, ECC_KEY_LEN);
    memcpy(concator + ECC_KEY_LEN, pubkey_point, xLen);
    memcpy(concator + ECC_KEY_LEN + xLen, pubkey_point+ECC_KEY_LEN, yLen);
    wc_Sha256Update(sha, concator, ECC_KEY_LEN + xLen + yLen);
    wc_Sha256Final(sha, M);
				
    //print_hex(M, sizeof(M));

    /* Send (M, aid_x, aid_y, f) to the server */
    uint8_t buf[MAX_MSG_LEN] = {};

    memcpy(buf, M, sizeof(M));
    memcpy(buf + sizeof(M), aid_x, sizeof(aid_x));
    memcpy(buf + sizeof(M) + sizeof(aid_x), aid_y, sizeof(aid_y));
    memcpy(buf + sizeof(M) + sizeof(aid_x) + sizeof(aid_y), f, ECC_KEY_LEN);
    
	ret = write(sockfd, buf, ECC_KEY_LEN*4);

    if (ret != ECC_KEY_LEN*4) {
        printf("write may failed\n");
	return -1;
    }

    /* Wait server send reply message */
    ret = read(sockfd, buf, ECC_KEY_LEN*4);
    if (ret != ECC_KEY_LEN*4) {
        printf("read may failed\n");
	return -1;
    }
    /* Convert buf into server_M, server_aid_x, server_aid_y, server_f */
    uint8_t server_M[ECC_KEY_LEN] = {};
    uint8_t server_aid_x[ECC_KEY_LEN] = {};
    uint8_t server_aid_y[ECC_KEY_LEN] = {};
    uint8_t server_f[ECC_KEY_LEN] = {};

    memcpy(server_M, buf, sizeof(server_M));
    memcpy(server_aid_x, buf + sizeof(server_M), sizeof(server_aid_x));
    memcpy(server_aid_y, buf + sizeof(server_M) + sizeof(server_aid_x), sizeof(server_aid_y));
    memcpy(server_f, buf + sizeof(server_M) + sizeof(server_aid_x) + sizeof(server_aid_y), sizeof(server_f));

    // Bx_re = server_aid_x ^ aid
    // By_re = server_aid_y ^ aid
    uint8_t server_pubkey_point[ECC_KEY_LEN*2] = {};

    do_xor(server_pubkey_point, server_aid_x, aid, ECC_KEY_LEN);
    do_xor(server_pubkey_point + ECC_KEY_LEN, server_aid_y, aid, ECC_KEY_LEN);

    //print_hex(server_pubkey_point, ECC_KEY_LEN);
    //print_hex(server_pubkey_point + ECC_KEY_LEN, ECC_KEY_LEN);

    // server_aid_re = server_f ^ hash(Ax||By_re)
    uint8_t server_aid[ECC_KEY_LEN] = {};

    memcpy(concator, pubkey_point, xLen);
    memcpy(concator + xLen, server_pubkey_point + ECC_KEY_LEN, yLen);
    wc_Sha256Update(sha, concator, xLen + yLen);
    wc_Sha256Final(sha, hash);
    do_xor(server_aid, server_f, hash, sizeof(server_aid));

    //print_hex(server_aid, sizeof(server_aid));

    // Check if hash(server_aid_re||Bx_re||By_re) equals to server_M
    memcpy(concator, server_aid, sizeof(server_aid));
    memcpy(concator + sizeof(server_aid), server_pubkey_point, xLen);
    memcpy(concator + sizeof(server_aid) + xLen, server_pubkey_point + ECC_KEY_LEN, yLen);
    wc_Sha256Update(sha, concator, ECC_KEY_LEN*3);
    wc_Sha256Final(sha, hash);

    for (int i=0; i<sizeof(hash); ++i) {
        if (hash[i] != server_M[i]) {
	    printf("Wrong, terminate!\n");
	    return -1;
	}
    }

    /* Create shared key */
    ecc_key server_pubkey;
    wc_ecc_init(&server_pubkey);
    server_pubkey.rng = rng;
    key.rng = rng;
    ret = wc_ecc_import_unsigned(&server_pubkey, server_pubkey_point, server_pubkey_point + ECC_KEY_LEN, NULL, 7);
    if (ret != MP_OKAY) {
        printf("wc_ecc_import_raw failed %d\n", ret);
	return -1;
    }
    word32 secret_size = ECC_KEY_LEN;
    ret = wc_ecc_shared_secret(&key, &server_pubkey, SK, &secret_size);
    if (ret != 0) {
    printf("shared_secret failed %d\n", ret);
    }

    return 0;
}

int config_ktls(int infd, const uint8_t *session_key)
{
    unsigned long seq;
    memset(&seq, 0, TLS_CIPHER_AES_GCM_256_REC_SEQ_SIZE);

    unsigned char iv[TLS_CIPHER_AES_GCM_256_IV_SIZE];
    memset(iv, 0, TLS_CIPHER_AES_GCM_256_IV_SIZE);
    
    struct tls12_crypto_info_aes_gcm_256 crypto_info;
    if (setsockopt(infd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        printf("ERROR: failed to set TCP_ULP\n");
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

/* Wait for server's request, and send Modbus/TCP query to sensor */
void do_communication(int sockfd)
{
    double t1 = tvgetf();
    double t2;
    int ret;
    char msg[512] = {0};

    int in = 0;
    int out = 0;
    while (1) {
        ret = write(sockfd, msg, sizeof(msg));
	out += 1;
	ret = read(sockfd, msg, sizeof(msg));
	in += 1;
	t2 = tvgetf();
	if ((t2-t1) >= 10) {
	    pthread_mutex_lock(&mutex);
	    outn += out;
	    inn += in;
	    pthread_mutex_unlock(&mutex);
	    //printf("about to stop comm\n");
	    break;
	}
	/*if (ret != sizeof(msg)) {
	    printf("Something went wrong\n");
	} else {
	    print_hex(msg, ret);
	    printf("\n");
	}

	sleep(5);*/
    }
}

void *client_thread()
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    int ret; 
    int sockfd = 0;

    /* Create Socket */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1){
        perror("Fail to create a socket.");
        return NULL;
    }

    /* Authentication Phase */
    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;
    info.sin_addr.s_addr = inet_addr(HOST);
    info.sin_port = htons(PORT);

    //printf("Connect to server side...\n");
    ret = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(ret == -1){
        perror("Connection error\n");
	return NULL;
    }

    //printf("Communication Phase...\n");
    do_communication(sockfd);
    
    close(sockfd);
    return 0;
}

int main()
{
    pthread_t thread[10];
    int num = 10;
    for (int i=0; i<num; i++) {
        pthread_create(&thread[i], NULL, &client_thread, NULL);
    }
    //sleep(5);
    for (int j=0; j < num; j++) {
        pthread_join(thread[j], NULL);
    }

    printf("outn: %d\ninn: %d\n", outn, inn);
    return 0;
}

