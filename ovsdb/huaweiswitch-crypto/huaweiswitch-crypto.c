#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <termios.h>

#include "huaweiswitch-key.h"

static int unix_sock(void)
{
    int sock;
    struct sockaddr_un address;
    size_t addrLength;

    //创建unix domain socket
    if ((sock = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        printf("socket");
        return -1;
    }

    //设置socket地址
    address.sun_family = AF_UNIX;    /* Unix domain socket */
    strcpy(address.sun_path, SOCKET_FILE);

    /* The total length of the address includes the sun_family
       element */
    addrLength = sizeof(address.sun_family) +
                 strlen(address.sun_path);

    //连接服务器
    if (connect(sock, (struct sockaddr *) &address, addrLength)) {
        printf("connect");
        return -1;
    }

    return sock;
}

static int send_msg(int sock, unsigned int crypt, unsigned char * string, unsigned int len)
{
    char * sendmsg = NULL;
    CryptMSGHead * sendHead;
    int size;

    sendmsg = (char *)malloc(sizeof(CryptMSGHead) + len);
    if (NULL == sendmsg) {
        return -1;
    }

    sendHead = (CryptMSGHead *)(void *)sendmsg;
    sendHead->crypt = crypt;
    sendHead->len = len;

    (void)memcpy(sendmsg+sizeof(CryptMSGHead), string, len);

    size = send(sock, sendmsg, len + sizeof(CryptMSGHead), 0);
    if(size < 0) {
        printf("Data length [%d] sended.\n", size);
        free(sendmsg);
        return -1;
    }

    free(sendmsg);
    return 0;
}

static int rec_msg(int sock, unsigned char ** result, unsigned int * len)
{
    CryptMSGHead recHead = {0};
    unsigned char * recvmsg = NULL;
    int size;

    size = recv(sock, &recHead, sizeof(CryptMSGHead), 0);
    if(size < 0) {
        printf("Error: recv head [%d].\n", size);
        return -1;
    }

    if (recHead.crypt != RESULT) {
        return -1;
    }

    recvmsg = (char *)malloc(recHead.len);
    if (NULL == recvmsg) {
        return -1;
    }

    size = recv(sock, recvmsg, recHead.len, 0);
    if(size < 0) {
        printf("Error: recv [%d].\n", size);
        free(recvmsg);
        return -1;
    }

    *result = recvmsg;
    *len = recHead.len;

    return 0;
}

static int crypto(unsigned int type, unsigned char * in, unsigned int in_len, unsigned char ** out, unsigned int * out_len)
{
    int sock;

    if ((type > DECRTPT) || 
        (NULL == in) ||
        (0 == in_len) ||
        (NULL == out) ||
        (NULL == out_len)) {
        return -1;
    }

    sock = unix_sock();
    if (sock < 0) {
        return -1;
    }

    if (send_msg(sock, type, in, in_len) < 0) {
        printf("Error: Send.\n");
        close(sock);
        return -1;
    }

    if (rec_msg(sock, out, out_len) < 0) {
        printf("Error: rec.\n");
        close(sock);
        return -1;
    }

    close(sock);

    return 0;
}

int Encrypto(unsigned char * in, unsigned int in_len, unsigned char ** out, unsigned int * out_len)
{
    return crypto(ENCRTPT, in, in_len, out, out_len);
}

int Decrypto(unsigned char * in, unsigned int in_len, unsigned char ** out, unsigned int * out_len)
{
    return crypto(DECRTPT, in, in_len, out, out_len);
}

static int mygetch()
{
    struct termios oldt,newt;
    int ch;
    tcgetattr(STDIN_FILENO,&oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON |ECHO);
    tcsetattr(STDIN_FILENO,TCSANOW,&newt);
    ch = getchar();
    tcsetattr(STDIN_FILENO,TCSANOW,&oldt);
    return ch;
}

void Getpassword(char * password, unsigned int * length)
{
    int len = 0;
    char c;
    while(len < *length) {
        c = mygetch();
        if(c == '\n') {
            password[len++] = '\0';
            printf("\n");
            break;
        }
        if(c == '\b') {
            //printf("\b");
            len--;
        }
        else {
            password[len++] = c;
            //printf("*");
        }
    }

    *length = len;

    return;
}

