#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <linux/tls.h>
#include <sys/socket.h>
#include <netinet/tcp.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

#define ECC_KEY_LEN 32 // byte
#define MAX_MSG_LEN 4096


void do_xor(uint8_t *out, const uint8_t *lhs, const uint8_t *rhs, int len)
{
    for(int i=0; i<len; ++i) {
        /* Accept a connection from client */
        out[i] = lhs[i] ^ rhs[i];
    }
}

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

int do_authentication(char *buf, int buf_size, uint8_t *session_key, const uint8_t *psk, const uint8_t *aid, RNG *rng, Sha256 *sha)
{
    //uint8_t buf[MAX_MSG_LEN] = {};
    uint8_t concator[ECC_KEY_LEN*3] = {};
    uint8_t hash[ECC_KEY_LEN] = {};
    
    int ret = 0;
    // Wait for client TODO: Put this outside
    /*ret = read(infd, buf, ECC_KEY_LEN*4);
    if (ret != ECC_KEY_LEN*4) {
        perror("do_authentication read");
        return -1;
    }*/
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
    /*ret = write(infd, buf, ECC_KEY_LEN*4);
    if (ret < ECC_KEY_LEN*4) {
        printf("write may failed\n");
	return -1;
    }*/

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
