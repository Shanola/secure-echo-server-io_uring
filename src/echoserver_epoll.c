#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <linux/tls.h>
#include <netinet/tcp.h>

//Wolfcrypt
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "secure.h"

// socket
#define LISTENQ 10240
#define PORT 12345
#define ECC_KEY_LEN 32
#define AUTH_MSG_LEN ECC_KEY_LEN*4
#define MAX_MSG_LEN 4096

// epoll
#define MAXEVENTS 10240 

#define AUTH_SUCCESS 0


enum {
    INIT = 0, // initialization phase
    REG,  // registration phase
    AUTH, // authentication phase
    COMM  // communication phase
};

typedef struct {
    char *str;
    int phase;
    int flag;
    char *status;
    int entity; // 1 == client, 0 == server
} Msg;

typedef struct {
    int fd;
    int epfd;
    int next_event;
    char buf[MAX_MSG_LEN];
    uint8_t session_key[ECC_KEY_LEN];
} sock_info_t;


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

void print_log(const Msg msg)
{
    return;
    if (!msg.flag) return;

    // time
    time_t rawtime;
    struct tm *timeinfo;
    time (&rawtime);
    timeinfo = localtime(&rawtime);
    char *timestr = asctime(timeinfo);
    timestr[strlen(timestr) - 1] = '\0';
    printf("[%s]", timestr);

    // phase
    printf("[PHASE %d]", msg.phase);

    // client or server?
    if (msg.entity == 2) {
        printf("[%s]", "Global"); // 
    } else {
        printf("[%s]", msg.entity ? "Client" : "Server"); // 1 == client, 0 == server
    }
    // status
    printf("[%s]", msg.status);
    // msg
    printf(" %s", msg.str);
    //if (msg.str[strlen(msg.str)-1] != '\n') printf("\n");
}

void print_hex(const uint8_t *s, int len, int flag)
{
    return;
    if (!flag) return;
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", s[i]);
    }
    printf("\n");
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

/* set a socket non-blocking. If a listen socket is a blocking socket, after
 * it comes out from epoll and accepts the last connection, the next accpet
 * will block unexpectedly.
 */
static int sock_set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        printf("fcntl error\n");
	//log_err("fcntl");
        return -1;
    }

    flags |= O_NONBLOCK;
    int s = fcntl(fd, F_SETFL, flags);
    if (s == -1) {
        printf("fcntl error\n");
        //log_err("fcntl");
        return -1;
    }
    return 0;
}

int main()
{
    if (sigaction(SIGPIPE, &(struct sigaction){.sa_handler = SIG_IGN, .sa_flags = 0}, NULL)) {
        printf("Failed to install signal handler for SIGPIPE\n");
	//log_err("Failed to install sigal handler for SIGPIPE"); //TODO: typo
        return -1;
    }

    int ret;
    int logflag = 1; //TODO

    // Log structure
    Msg log;
    log.flag = logflag;

    int listenfd = open_listenfd(PORT);
    ret = sock_set_non_blocking(listenfd);
    assert(ret == 0 && "sock_set_non_blocking");

    // create epoll
    int epfd = epoll_create1(0);
    assert(epfd > 0 && "epoll_create1");

    struct epoll_event *events = malloc(sizeof(struct epoll_event) * MAXEVENTS);
    assert(events && "epoll_event: malloc");

    sock_info_t *sock_info = malloc(sizeof(sock_info_t));
    sock_info->fd = listenfd;
    sock_info->epfd = epfd;
    sock_info->next_event = 777;

    struct epoll_event event = {
        .data.ptr = sock_info,
	.events = EPOLLIN | EPOLLET,
    };
    epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &event);
    
    /* Server Initialization */
    RNG rng[1];
    Sha256 sha[1];

    log.phase = INIT;
    log.status = "Info";
    log.entity = 2;
    log.str = "Init random number generator\n";
    print_log(log);
    if (wc_InitRng(rng) != 0) {
        log.status = "ERR";
        log.str = "Rng init failed";
        print_log(log);
	return -1;
    }

    log.str = "Init hash function\n";
    print_log(log);
    if ( wc_InitSha256(sha) != 0) {
        log.status = "ERR";
        log.str = "Hash init failed\n";
	print_log(log);
	return -1;
    }

    printf("Server registration...\n");
    // authentication variables
    uint8_t psk[ECC_KEY_LEN] = {};
    uint8_t aid[ECC_KEY_LEN] = {};

    /* Registration Phase                            /
    /  Connect and register to authentication server */
    ret = do_registration(listenfd, psk, aid, rng, sha);
    if (ret != 0) {
        printf("registration phase failed\n");
	return -1;
    }
    printf("Server start, wait for connections. listenfd: %d\n", listenfd);

    /* Accept connections from client */
    while (1) {
        int n = epoll_wait(epfd, events, MAXEVENTS, -1);
	for (int i = 0; i < n; i++) {
	    sock_info_t *s = events[i].data.ptr;
	    if (s->fd == listenfd) {
	        /* Got one or more connections */
		while (1) {
		    struct sockaddr_in clientaddr;
		    socklen_t inlen = sizeof(clientaddr);
	            int infd = accept(listenfd, (struct sockaddr *) &clientaddr, &inlen);
		    //printf("accept: infd=%d\n", infd);
		    if (infd < 0) {
			 if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                            /* we have processed all incoming connections */
                            break;
                        }
			printf("accept error\n");
			break;                        
		    }

		    ret = sock_set_non_blocking(infd);
		    assert(ret == 0 && "sock_set_non_blocking");

		    sock_info_t *sock_info = malloc(sizeof(sock_info_t));
		    if (!sock_info) {
		        printf("sock_info malloc failed\n");
			break;
		    }
		    sock_info->fd = infd;
		    sock_info->epfd = epfd;
		    sock_info->next_event = AUTH;
		    event.data.ptr = sock_info;
		    //memcpy(event.data.ptr, sock_info, sizeof(sock_info));
		    event.events = EPOLLIN | EPOLLET | EPOLLONESHOT;
		    epoll_ctl(epfd, EPOLL_CTL_ADD, infd, &event);
		}
	    } else {
	        if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP) ||
                    (!(events[i].events & EPOLLIN))) {
                    printf("epoll error fd: %d\n", s->fd);
		    //log_err("epoll error fd: %d", r->fd);
                    close(s->fd);
                    continue;
                } else if(s->next_event == AUTH) {
		    // read
		    int n=0;
		    /*int nread=0;
		    while ((nread = read(s->fd, s->buf + n, AUTH_MSG_LEN)) > 0) {
		        n += nread;    
		    }*/
		    n = read(s->fd, s->buf, AUTH_MSG_LEN);
		    if (n == 0) {
		        /*EOF*/
			continue;
		    }
		    if (n < 0) {
		        if (errno != EAGAIN) {
		            /*error*/
		        }
			continue;
       		    }
		    ret = do_authentication(s->buf, sizeof(s->buf), s->session_key, psk, aid, rng, sha); //give s->buf, s->session_key
		    if (ret != AUTH_SUCCESS) {
			close(s->fd);
			continue;
		    }
		    
		    /*uint8_t *bufp = s->buf;
		    for (size_t nleft = AUTH_MSG_LEN; nleft > 0; nleft -= n) {
		        if (n = write(s->fd, bufp, nleft) <= 0) {
			    printf("~~n = %d\n", n);
			    if (errno == EINTR) {
			        n = 0;
			    } else {
			        printf("do_auth write may failed: %s\n", strerror(errno));
				break;
			    }
			}
			printf("n = %d\n", n);
			bufp += n;
		    }*/
		    n = write(s->fd, s->buf, AUTH_MSG_LEN);
		    config_ktls(s->fd, s->session_key);

		    s->next_event = COMM;
		} else if(s->next_event == COMM) {
		    int bytes_received = read(s->fd, s->buf, MAX_MSG_LEN);
		    if (bytes_received <= 0) {
		        epoll_ctl(s->epfd, EPOLL_CTL_DEL, s->fd, NULL);
			shutdown(s->fd, SHUT_RDWR);
		    } else {
		        write(s->fd, s->buf, bytes_received);
		    }
		} else {
		    printf("why I am here?\n");
		} 
		struct epoll_event event = {
		.data.ptr = s,
		.events = EPOLLIN | EPOLLET | EPOLLONESHOT,
		};
		epoll_ctl(s->epfd, EPOLL_CTL_MOD, s->fd, &event);
	    }
	}
    }
    return 0;
}

