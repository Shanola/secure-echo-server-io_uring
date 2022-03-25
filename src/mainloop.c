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

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/aes.h>

#include <liburing.h>

#include "secure.h"

#define PORT 12345
#define LISTENQ 4096
#define IOURING_QUEUE_DEPTH 8192
#define MAX_MSG_LEN 2048
#define AUTH_MSG_LEN ECC_KEY_LEN*4
#define MAX_CONNECTION 4096
#define BUFFERS_COUNT MAX_CONNECTION
#define ECC_KEY_LEN 32
#define AUTH_SUCCESS 0
#define AUTH_FAIL -1

char bufs[BUFFERS_COUNT][MAX_MSG_LEN] = {0};

enum {
    ACCEPT,
    AUTH_READ,
    AUTH_WRITE,
    CONFIG_KTLS,
    COMM_READ,
    COMM_WRITE,
    PROV_BUF,
};

typedef struct {
    /* socket */
    int infd;
    int listenfd; // listenfd
    /* wolfSSL */
    RNG rng[1]; // wolfssl
    Sha256 sha[1]; // wolfssl
    uint8_t psk[ECC_KEY_LEN]; // pre-shared key
    uint8_t aid[ECC_KEY_LEN]; // alias id
    char buf[MAX_MSG_LEN];
    uint8_t session_key[ECC_KEY_LEN];
    /* io_uring */
    int event_type;
    int bid;
} session_info_t;


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

void add_accept(struct io_uring *ring, int fd, struct sockaddr *client_addr, socklen_t *client_len, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    session_info_t *session_info = malloc(sizeof(session_info_t));

    session_info->listenfd = fd;
    session_info->event_type = ACCEPT;
    
    io_uring_prep_accept(sqe, fd, (struct sockaddr *)client_addr, client_len, 0);
    io_uring_sqe_set_flags(sqe, flags);
    io_uring_sqe_set_data(sqe, session_info);
}

void add_auth_read(struct io_uring *ring, int sockfd, unsigned gid, size_t size, unsigned flags) // Similar to add_read, except for the event_type == AUTH_READ
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    sqe->buf_group = gid;
    session_info_t *session_info = malloc(sizeof(session_info_t));
    
    session_info->infd = sockfd;
    session_info->event_type = AUTH_READ;

    io_uring_prep_recv(sqe, sockfd, NULL, size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    io_uring_sqe_set_data(sqe, session_info);

}

void add_auth_write(struct io_uring *ring, int sockfd, uint8_t *session_key, int key_size, int bid, int size, unsigned flags) // Similar to add_write, except for the buf and event_type == AUTH_WRITE 
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    session_info_t *session_info = malloc(sizeof(session_info_t));

    session_info->infd = sockfd;
    session_info->event_type = AUTH_WRITE;
    memcpy(session_info->session_key, session_key, key_size);
    session_info->bid = bid;

    io_uring_prep_send(sqe, sockfd, &bufs[bid], size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    io_uring_sqe_set_data(sqe, session_info);
}

void add_read(struct io_uring *ring, int fd, unsigned gid, size_t size, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    sqe->buf_group = gid;
    session_info_t *session_info = malloc(sizeof(session_info_t));

    session_info->infd = fd;
    session_info->event_type = COMM_READ;
    io_uring_prep_recv(sqe, fd, NULL, size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    io_uring_sqe_set_data(sqe, session_info);

}

void add_write(struct io_uring *ring, int fd, int bid, size_t size, unsigned flags)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    session_info_t *session_info = malloc(sizeof(session_info_t));

    session_info->infd = fd;
    session_info->event_type = COMM_WRITE;
    session_info->bid = bid;

    io_uring_prep_send(sqe, fd, &bufs[bid], size, 0);
    io_uring_sqe_set_flags(sqe, flags);
    io_uring_sqe_set_data(sqe, session_info);
    
}
void add_provide_buffers(struct io_uring *ring, int bid, int gid, unsigned msg_size, int buf_cnt)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);

    session_info_t *session_info = malloc(sizeof(session_info_t));
    session_info->infd = 0;
    session_info->event_type = PROV_BUF;
    io_uring_prep_provide_buffers(sqe, bufs[bid], msg_size, buf_cnt, gid, bid);
    io_uring_sqe_set_data(sqe, session_info);
}


int main()
{
    /* when a fd is closed by remote, writing to this fd will cause system
     * send SIGPIPE to this process, which exit the program
     */
    if (sigaction(SIGPIPE, &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0}, NULL)) {
        printf("Failed to install sigal handler for SIGPIPE");
        return 0;
    }

    int ret;
    int group_id = 0;
    int listenfd = open_listenfd(PORT);

    /* Initialize wolfSSL */
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
    printf("Registration Phase\n");

    uint8_t psk[ECC_KEY_LEN] = {};
    uint8_t aid[ECC_KEY_LEN] = {};

    ret = do_registration(listenfd, psk, aid, rng, sha);
    if (ret != 0) {
        printf("registration phase failed\n");
        return -1;
    }

    /* Initialize io_uring */
    struct io_uring ring;
    struct io_uring_params params;
    memset(&params, 0, sizeof(params));

    if (io_uring_queue_init_params(IOURING_QUEUE_DEPTH, &ring, &params) < 0) {
        perror("io_uring init failed\n");
	return 0;
    }

    // check if IORING_FEAT_FAST_POLL is supported
    if (!(params.features & IORING_FEAT_FAST_POLL)) {
        printf("IORING_FEAT_FAST_POLL not available in the kernel, quiting...\n");
        exit(0);
    }

    // check if buffer selection is supported
    struct io_uring_probe *probe;
    probe = io_uring_get_probe_ring(&ring);
    if (!probe || !io_uring_opcode_supported(probe, IORING_OP_PROVIDE_BUFFERS)) {
        printf("Buffer select not supported, skipping...\n");
        exit(0);
    }
    free(probe);

    // register buffers for buffer selection
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_provide_buffers(sqe, bufs, MAX_MSG_LEN, BUFFERS_COUNT, group_id, 0);

    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    if (cqe->res < 0) {
        printf("cqe->res = %d\n", cqe->res);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);


    // add first accept SQE to monitor new incoming connections
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    printf("Server start\n");
    add_accept(&ring, listenfd, (struct sockaddr *)&client_addr, &client_len, 0);

    while (1) {
        io_uring_submit_and_wait(&ring, 1);
	struct io_uring_cqe *cqe;
	unsigned head;
	unsigned count = 0;

	// go through all CQEs
	io_uring_for_each_cqe(&ring, head, cqe) {
	    count++;
	    if (cqe->res == -ENOBUFS) {
                fprintf(stdout, "bufs in automatic buffer selection empty, this should not happen\n");
                fflush(stdout);
                return 0;
            }
	    session_info_t *session_info = io_uring_cqe_get_data(cqe);

	    int type = session_info->event_type;
	    if (type == PROV_BUF) {
	        //printf("[PROV_BUF]\n");
                if (cqe->res < 0) {
                    printf("cqe->res = %d\n", cqe->res);
                    return 0;
                }
            } else if (type == ACCEPT) {
	        //printf("[ACCEPT]\n");
                int sock_conn_fd = cqe->res;

                // only auth_read when there is no error, >= 0
                if (sock_conn_fd >= 0) {
                    add_auth_read(&ring, sock_conn_fd, group_id, AUTH_MSG_LEN, IOSQE_BUFFER_SELECT);
		} else {
		    printf("No?\n");
		}
                // new connected client; read data from socket and re-add accept to monitor for new connections
                add_accept(&ring, listenfd, (struct sockaddr *)&client_addr, &client_len, 0);
            } else if (type == AUTH_READ) {
	        //printf("[AUTH_READ]\n");
	        // extract read authentication request of client from buffer
		int nbytes = cqe->res;
		int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
		if (nbytes <= 0) {
		    printf("read may fail\n");
		    // read from auth_read may failed
		    add_provide_buffers(&ring, bid, group_id, MAX_MSG_LEN, 1);
		    close(session_info->infd);
		} else {
		    /* Take out msg from the buffer, and do authenticaiton */
		    if (do_authentication(bufs[bid], MAX_MSG_LEN, session_info->session_key, psk, aid, rng, sha) != AUTH_SUCCESS) {  // obtain shared session key, <msg> to send to client
		        close(session_info->infd); // auth failed, terminate this connection
		    } else {
		        add_auth_write(&ring, session_info->infd, session_info->session_key, ECC_KEY_LEN, bid, AUTH_MSG_LEN, 0); // write <msg> to client
		    }
		}
	    } else if (type == AUTH_WRITE) {
	        //printf("[AUTH_WRITE]\n");
	        add_provide_buffers(&ring, session_info->bid, group_id, MAX_MSG_LEN, 1);
		config_ktls(session_info->infd, session_info->session_key);
		add_read(&ring, session_info->infd, group_id, MAX_MSG_LEN, IOSQE_BUFFER_SELECT);
	    } else if (type == COMM_READ) {
	        //printf("[COMM_READ]\n");
	        int nbytes = cqe->res;
		int bid = cqe->flags >> 16;
		if (nbytes <= 0) {
		    // read from client may failed
		    add_provide_buffers(&ring, bid, group_id, MAX_MSG_LEN, 1);
		    close(session_info->infd);
		} else {
		    add_write(&ring, session_info->infd, bid, nbytes, 0);
		}
            } else if (type == COMM_WRITE) {
	        //printf("[COMM_WRITE]\n");
	        add_provide_buffers(&ring, session_info->bid, group_id, MAX_MSG_LEN, 1);
		add_read(&ring, session_info->infd, group_id, MAX_MSG_LEN, IOSQE_BUFFER_SELECT);
            }
	}
	io_uring_cq_advance(&ring, count);
    }
}


